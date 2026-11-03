#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 abruption
# 파일 경로·ACL·볼륨·무결성 검사는 NoAdKakaoMac의 MIT 코드에서 가져왔습니다.
"""NoAdKakaoMac 전체 백업을 이용한 공식 카카오톡 복원 도구."""
import argparse
import contextlib
import ctypes
import errno
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import sys

VERSION = '0.1.0-rc.1'
BUNDLE_ID = 'com.kakao.KakaoTalkMac'
TEAM_ID = 'L75WVXX68A'
# Apple의 공식 배포 서명과 카카오 앱 식별자를 인증합니다.
OFFICIAL_REQUIREMENT = ('= (anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists '
                        'or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
                        'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
                        'and certificate leaf[subject.OU] = "L75WVXX68A") '
                        'and identifier "com.kakao.KakaoTalkMac"')
INFO = Path('Contents/Info.plist')
EXE = Path('Contents/MacOS/KakaoTalk')

class RestoreError(RuntimeError):
    def __init__(self, message, code='OPERATION_FAILED'):
        super().__init__(message)
        self.code = code


_ACL_LIBRARY = None
_STATFS_LIBRARY = None
_VOLUME_POLICIES = {}
_ACL_WRITE_MASK = sum(1 << bit for bit in (2, 4, 5, 6, 8, 10, 12, 13))


def _darwin_acl(fd):
    """열린 객체의 확장 ACL만 읽습니다. 이름 문자열을 다시 따라가지 않습니다."""
    if sys.platform != 'darwin':
        return []  # 지원 호스트 검사는 별도이며, 비macOS 합성 시험에는 Darwin ACL이 없습니다.
    global _ACL_LIBRARY
    if _ACL_LIBRARY is None:
        library = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        signatures = {
            'acl_get_fd_np': ([ctypes.c_int, ctypes.c_int], ctypes.c_void_p),
            'acl_valid': ([ctypes.c_void_p], ctypes.c_int),
            'acl_get_entry': ([ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)], ctypes.c_int),
            'acl_get_tag_type': ([ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)], ctypes.c_int),
            'acl_get_permset_mask_np': ([ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)], ctypes.c_int),
            'acl_get_qualifier': ([ctypes.c_void_p], ctypes.c_void_p),
            'acl_free': ([ctypes.c_void_p], ctypes.c_int),
            'mbr_uuid_to_id': ([ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_int)], ctypes.c_int),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(library, name)
            function.argtypes, function.restype = arguments, result
        _ACL_LIBRARY = library
    library = _ACL_LIBRARY
    acl = library.acl_get_fd_np(fd, 0x100)  # Darwin SDK의 ACL_TYPE_EXTENDED
    if not acl:
        if ctypes.get_errno() == errno.ENOENT and os.fstat(fd).st_nlink > 0:
            return []  # 유효한 열린 객체에 저장된 확장 ACL 자체가 없는 경우입니다.
        raise OSError(ctypes.get_errno(), '확장 ACL을 읽을 수 없습니다')
    try:
        if library.acl_valid(acl):
            raise RestoreError('객체의 확장 ACL이 올바르지 않습니다')
        entries = []
        for index in range(1024):
            entry = ctypes.c_void_p()
            ctypes.set_errno(0)
            result = library.acl_get_entry(acl, 0 if index == 0 else -1, ctypes.byref(entry))
            if result:
                if ctypes.get_errno() == errno.EINVAL:
                    return entries  # Darwin은 마지막 항목 뒤에 EINVAL을 반환합니다.
                raise OSError(ctypes.get_errno(), 'ACL 항목을 읽을 수 없습니다')
            tag, mask = ctypes.c_int(), ctypes.c_uint64()
            if (library.acl_get_tag_type(entry, ctypes.byref(tag)) or
                    library.acl_get_permset_mask_np(entry, ctypes.byref(mask))):
                raise OSError(ctypes.get_errno(), 'ACL 권한을 읽을 수 없습니다')
            if tag.value not in (1, 2):
                raise RestoreError('지원하지 않는 ACL 항목 형식입니다')
            principal = library.acl_get_qualifier(entry)
            if not principal:
                raise OSError(ctypes.get_errno(), 'ACL 주체를 읽을 수 없습니다')
            try:
                identifier, kind = ctypes.c_uint32(), ctypes.c_int()
                mapped = library.mbr_uuid_to_id(principal, ctypes.byref(identifier), ctypes.byref(kind)) == 0
                entries.append((tag.value, kind.value if mapped else -1,
                                identifier.value if mapped else -1, mask.value))
            finally:
                library.acl_free(principal)
        raise RestoreError('확장 ACL 항목 수가 제한을 넘었습니다')
    finally:
        library.acl_free(acl)


class _DarwinStatFS(ctypes.Structure):
    """Darwin SDK sys/mount.h의 64비트 struct statfs 레이아웃입니다."""
    _fields_ = [
        ('f_bsize', ctypes.c_uint32), ('f_iosize', ctypes.c_int32),
        ('f_blocks', ctypes.c_uint64), ('f_bfree', ctypes.c_uint64),
        ('f_bavail', ctypes.c_uint64), ('f_files', ctypes.c_uint64),
        ('f_ffree', ctypes.c_uint64), ('f_fsid', ctypes.c_int32 * 2),
        ('f_owner', ctypes.c_uint32), ('f_type', ctypes.c_uint32),
        ('f_flags', ctypes.c_uint32), ('f_fssubtype', ctypes.c_uint32),
        ('f_fstypename', ctypes.c_char * 16),
        ('f_mntonname', ctypes.c_char * 1024), ('f_mntfromname', ctypes.c_char * 1024),
        ('f_flags_ext', ctypes.c_uint32), ('f_reserved', ctypes.c_uint32 * 7),
    ]


def _volume_mountpoint(fd):
    """경로 문자열 대신 열린 객체의 실제 볼륨 마운트 지점을 조회합니다."""
    if sys.platform != 'darwin':
        raise OSError(errno.ENOTSUP, 'FD 볼륨 조회는 macOS에서만 지원합니다')
    global _STATFS_LIBRARY
    if _STATFS_LIBRARY is None:
        library = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        try:
            # x86_64 SDK의 __DARWIN_INODE64 선언은 별도 심볼로 연결됩니다.
            # 일반 fstatfs 심볼은 이전 레이아웃을 사용하므로 대체 호출하지 않습니다.
            symbol = 'fstatfs$INODE64' if platform.machine() == 'x86_64' else 'fstatfs'
            function = getattr(library, symbol)
        except AttributeError as error:
            raise OSError(errno.ENOSYS, 'FD 볼륨 조회 API를 사용할 수 없습니다') from error
        function.argtypes = [ctypes.c_int, ctypes.POINTER(_DarwinStatFS)]
        function.restype = ctypes.c_int
        library.fstatfs = function  # 캐시에서도 선택한 64비트 inode ABI만 호출합니다.
        _STATFS_LIBRARY = library
    value = _DarwinStatFS()
    if _STATFS_LIBRARY.fstatfs(fd, ctypes.byref(value)):
        raise OSError(ctypes.get_errno(), '열린 객체의 볼륨을 확인할 수 없습니다')
    raw = value.f_mntonname
    mount = os.fsdecode(raw)
    if not raw or len(raw) >= 1024 or not os.path.isabs(mount):
        raise ValueError('볼륨 마운트 지점 형식이 올바르지 않습니다')
    if os.stat(mount).st_dev != os.fstat(fd).st_dev:
        raise ValueError('마운트 지점과 열린 객체의 장치가 다릅니다')
    return mount


def _volume_policy(fd, path):
    """파일 시스템의 소유권 적용 여부를 장치별로 확인합니다."""
    if sys.platform != 'darwin':
        return {'owners': True, 'mount': '/'}
    device = os.fstat(fd).st_dev
    try:
        mount = _volume_mountpoint(fd)
        if os.stat(mount).st_dev != device:
            raise ValueError('조회할 볼륨과 열린 객체의 장치가 다릅니다')
        # APFS의 System/Data 경로가 같은 st_dev로 보일 수 있으므로 실제 마운트도 구분합니다.
        policies = _VOLUME_POLICIES.get(device, {})
        if mount not in policies:
            result = subprocess.run(['/usr/sbin/diskutil', 'info', '-plist', mount],
                                    capture_output=True, timeout=10)
            value = plistlib.loads(result.stdout) if result.returncode == 0 else None
            if not isinstance(value, dict) or not isinstance(value.get('GlobalPermissionsEnabled'), bool):
                raise ValueError('소유권 정보 없음')
            returned_mount = value.get('MountPoint')
            if (not isinstance(returned_mount, str) or not os.path.isabs(returned_mount)
                    or os.stat(returned_mount).st_dev != device
                    or os.fstat(fd).st_dev != device
                    or Path(returned_mount).resolve() != Path(mount).resolve()):
                raise ValueError('조회 결과의 볼륨과 열린 객체의 장치가 다릅니다')
            policy = {'owners': value['GlobalPermissionsEnabled'], 'mount': returned_mount}
            _VOLUME_POLICIES[device] = {**policies, mount: policy}
        return _VOLUME_POLICIES[device][mount]
    except (ValueError, plistlib.InvalidFileException, OSError, subprocess.TimeoutExpired) as error:
        raise RestoreError('볼륨의 소유권 적용 상태를 확인할 수 없습니다: ' + str(path),
                         'VOLUME_QUERY_FAILED') from error


class PathGuard:
    """신뢰한 부모 FD와 객체 신원을 확인하며 권한을 자동으로 고치지 않습니다."""
    def __init__(self, for_write=False):
        self.for_write = for_write
        self.euid = os.geteuid()
        self.uids = {0, self.euid}
        if self.euid == 0 and os.environ.get('SUDO_UID') is not None:
            try:
                caller = int(os.environ['SUDO_UID'])
                if not 0 <= caller < 2 ** 32:
                    raise ValueError('UID 범위 오류')
                pwd.getpwuid(caller)
                self.uids.add(caller)
            except (ValueError, KeyError) as error:
                raise RestoreError('sudo 호출자 UID를 확인할 수 없습니다') from error
        self.groups = {0}
        if sys.platform == 'darwin':
            try:
                self.groups.add(grp.getgrnam('admin').gr_gid)
            except KeyError:
                raise RestoreError('macOS 관리자 그룹을 확인할 수 없습니다')
        self.anchors = {}
        self.private_dirs = set()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        for fd, _ in self.anchors.values():
            os.close(fd)
        self.anchors.clear()
        self.private_dirs.clear()

    @staticmethod
    def identity(info):
        # 디렉터리의 mtime/nlink는 정상적인 자식 생성으로 바뀌므로 포함하지 않습니다.
        return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode),
                info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))

    def _check(self, fd, path, directory=False, private=False):
        info = os.fstat(fd)
        required = stat.S_ISDIR if directory else stat.S_ISREG
        if not required(info.st_mode):
            raise RestoreError('경로 객체의 형식이 올바르지 않습니다: ' + str(path))
        if info.st_uid not in self.uids:
            raise RestoreError('신뢰하지 않는 소유자의 경로입니다: ' + str(path))
        if not directory and info.st_nlink != 1:
            raise RestoreError('여러 하드링크가 있는 파일은 사용하지 않습니다: ' + str(path))
        policy = _volume_policy(fd, path)
        weak = not policy['owners']
        if weak and self.euid == 0 and self.for_write:
            raise RestoreError('관리자 쓰기에는 소유권을 적용하는 볼륨이 필요합니다: ' + str(path))
        mode = stat.S_IMODE(info.st_mode)
        if private and mode & 0o077:
            raise RestoreError('메타데이터와 백업은 사용자 전용 권한이어야 합니다: ' + str(path))
        sticky = directory and bool(mode & stat.S_ISVTX) and info.st_uid in self.uids
        if (mode & 0o002 and not sticky) or (mode & 0o020 and info.st_gid not in self.groups
                                              and not sticky and not (weak and self.euid != 0)):
            raise RestoreError('신뢰하지 않는 사용자가 쓸 수 있는 경로입니다: ' + str(path))
        try:
            acl = _darwin_acl(fd)
        except OSError as error:
            if weak and self.euid != 0 and error.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
                acl = []  # 비root 격리 시험의 소유권 비보장 한계는 문서에 명시합니다.
            else:
                raise RestoreError('ACL 검증에 실패했습니다: ' + str(path)) from error
        for tag, kind, identifier, mask in acl:
            trusted = (kind == 0 and identifier in self.uids) or (kind == 1 and identifier in self.groups)
            if tag == 1 and mask & (_ACL_WRITE_MASK if not private else 0xFFFFFFFFFFFFFFFF) and not trusted:
                raise RestoreError('신뢰하지 않는 주체의 쓰기 ACL이 있습니다: ' + str(path))
        return info

    def directory(self, path, create=False, private=False):
        path = safe_path(path)
        if private:
            self.private_dirs.add(path)
        if path in self.anchors:
            self.revalidate()
            self._check(self.anchors[path][0], path, directory=True, private=private)
            return self.anchors[path][0]
        parent = path.parent
        if path == parent:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        else:
            parent_fd = self.directory(parent, create=create)
            self.revalidate()
            try:
                fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(path.name, mode=0o700, dir_fd=parent_fd)
                fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            info = self._check(fd, path, directory=True, private=private)
        except BaseException:
            os.close(fd)
            raise
        self.anchors[path] = (fd, self.identity(info))
        self.revalidate()
        return fd

    def revalidate(self):
        for path, (fd, identity) in self.anchors.items():
            try:
                current = os.stat(path, follow_symlinks=False)
                if self.identity(current) != identity or self.identity(os.fstat(fd)) != identity:
                    raise RestoreError('작업 중 부모 경로의 신원이 변경됐습니다: ' + str(path))
                self._check(fd, path, directory=True, private=path in self.private_dirs)
            except FileNotFoundError as error:
                raise RestoreError('작업 중 부모 경로가 이동됐습니다: ' + str(path)) from error

    @contextlib.contextmanager
    def file(self, path, private=False, create=False, flags=os.O_RDONLY):
        path = safe_path(path)
        parent_fd = self.directory(path.parent)
        self.revalidate()
        options = flags | os.O_NOFOLLOW | os.O_NONBLOCK
        if create:
            options |= os.O_CREAT | os.O_EXCL
        fd = os.open(path.name, options, 0o600, dir_fd=parent_fd)
        try:
            first = self._check(fd, path, private=private)
            named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if self.identity(named) != self.identity(first) or named.st_nlink != first.st_nlink:
                raise RestoreError('파일을 여는 동안 신원이 변경됐습니다: ' + str(path))
            yield fd
            self.revalidate()
            final = self._check(fd, path, private=private)
            named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if self.identity(named) != self.identity(final) or named.st_nlink != final.st_nlink:
                raise RestoreError('파일을 사용하는 동안 신원이 변경됐습니다: ' + str(path))
        finally:
            os.close(fd)

    def replace(self, source, destination):
        source, destination = safe_path(source), safe_path(destination)
        src_fd, dst_fd = self.directory(source.parent), self.directory(destination.parent)
        self.revalidate()
        opened = []
        try:
            for path, parent_fd, required in ((source, src_fd, True), (destination, dst_fd, False)):
                try:
                    info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    if required:
                        raise
                    continue
                directory = stat.S_ISDIR(info.st_mode)
                if not (directory or stat.S_ISREG(info.st_mode)):
                    raise RestoreError('교체할 객체의 형식이 올바르지 않습니다: ' + str(path))
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if directory else 0)
                fd = os.open(path.name, flags, dir_fd=parent_fd)
                opened.append(fd)
                observed = self._check(fd, path, directory=directory)
                if self.identity(info) != self.identity(observed):
                    raise RestoreError('교체 직전 객체의 신원이 변경됐습니다: ' + str(path))
                if required:
                    before = observed
            self.revalidate()
            os.replace(source.name, destination.name, src_dir_fd=src_fd, dst_dir_fd=dst_fd)
            self.revalidate()
            after = os.stat(destination.name, dir_fd=dst_fd, follow_symlinks=False)
            if self.identity(before) != self.identity(after):
                raise RestoreError('교체 후 객체의 신원이 다릅니다: ' + str(destination))
        finally:
            for fd in opened:
                os.close(fd)

    def unlink(self, path, private=True, expected=None):
        path = safe_path(path)
        parent_fd = self.directory(path.parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        try:
            info = self._check(fd, path, private=private)
            named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (self.identity(named) != self.identity(info) or
                    expected is not None and self.identity(info) != expected):
                raise RestoreError('삭제할 파일의 신원이 변경됐습니다: ' + str(path))
            self.revalidate()
            os.unlink(path.name, dir_fd=parent_fd)
            if os.fstat(fd).st_nlink != 0:
                raise RestoreError('삭제 중 파일의 신원이 변경됐습니다: ' + str(path))
        finally:
            os.close(fd)


def run(*args):
    result = subprocess.run([str(arg) for arg in args], capture_output=True)
    if result.returncode:
        raise RestoreError('명령 실행 실패: ' + str(args[0]) + ': ' +
                         result.stderr.decode(errors='replace').strip())
    return result


def digest(path):
    h = hashlib.sha256()
    with PathGuard() as guard, guard.file(path) as fd:
        first = os.fstat(fd)
        for chunk in iter(lambda: os.read(fd, 1024 * 1024), b''):
            h.update(chunk)
        final = os.fstat(fd)
        if (first.st_size, first.st_mtime_ns) != (final.st_size, final.st_mtime_ns):
            raise RestoreError('읽는 동안 파일 내용이 변경됐습니다: ' + str(path))
    return h.hexdigest()


def read_regular(path, private=False):
    with PathGuard() as guard, guard.file(path, private=private) as fd:
        first = os.fstat(fd)
        blocks = []
        for block in iter(lambda: os.read(fd, 1024 * 1024), b''):
            blocks.append(block)
        final = os.fstat(fd)
        if (first.st_size, first.st_mtime_ns) != (final.st_size, final.st_mtime_ns):
            raise RestoreError('읽는 동안 파일 내용이 변경됐습니다: ' + str(path))
        return b''.join(blocks)


def safe_path(path):
    """상위 경로를 포함해 호출자가 지정한 심볼릭 링크를 따라가지 않습니다."""
    path = Path(os.path.abspath(os.path.expanduser(str(path))))
    for item in (path, *path.parents):
        if item.is_symlink():
            raise RestoreError('심볼릭 링크가 포함된 작업 경로는 사용할 수 없습니다: ' + str(item))
    return path


def tree_manifest(path):
    """권한·빈 디렉터리·프레임워크 심볼릭 링크 원문을 목록에 포함합니다."""
    path = Path(path)
    if path.is_symlink() or not path.is_dir():
        raise RestoreError('실제 앱 번들 디렉터리가 필요합니다: ' + str(path))
    result = {}
    def visit(item, fd, info):
        relative = item.relative_to(path).as_posix()
        result[relative] = {'kind': 'dir', 'mode': stat.S_IMODE(info.st_mode)}
        for name in sorted(os.listdir(fd)):
            child = item / name
            original = os.stat(name, dir_fd=fd, follow_symlinks=False)
            mode = stat.S_IMODE(original.st_mode)
            key = child.relative_to(path).as_posix()
            if stat.S_ISLNK(original.st_mode):
                if original.st_uid not in guard.uids:
                    raise RestoreError('신뢰하지 않는 소유자의 링크입니다: ' + str(child))
                target = os.readlink(name, dir_fd=fd)
                try:
                    (child.parent / target).resolve().relative_to(path.resolve())
                except ValueError:
                    raise RestoreError('번들 밖을 가리키는 심볼릭 링크가 있습니다: ' + str(child))
                result[key] = {'kind': 'link', 'target': target, 'mode': mode}
            elif stat.S_ISDIR(original.st_mode) or stat.S_ISREG(original.st_mode):
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if stat.S_ISDIR(original.st_mode):
                    flags |= os.O_DIRECTORY
                child_fd = os.open(name, flags, dir_fd=fd)
                try:
                    observed = guard._check(child_fd, child, directory=stat.S_ISDIR(original.st_mode))
                    if guard.identity(original) != guard.identity(observed):
                        raise RestoreError('트리 항목의 신원이 변경됐습니다: ' + str(child))
                    if stat.S_ISDIR(original.st_mode):
                        visit(child, child_fd, observed)
                    else:
                        h = hashlib.sha256()
                        for block in iter(lambda: os.read(child_fd, 1024 * 1024), b''):
                            h.update(block)
                        after = os.fstat(child_fd)
                        if (observed.st_size, observed.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                            raise RestoreError('읽는 동안 트리 파일이 변경됐습니다: ' + str(child))
                        result[key] = {'kind': 'file', 'sha256': h.hexdigest(),
                                       'size': observed.st_size, 'mode': mode}
                finally:
                    os.close(child_fd)
            else:
                raise RestoreError('지원하지 않는 번들 항목입니다: ' + str(child))
            after = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if guard.identity(original) != guard.identity(after):
                raise RestoreError('트리 항목의 신원이 변경됐습니다: ' + str(child))
    with PathGuard() as guard:
        fd = guard.directory(path)
        visit(path, fd, os.fstat(fd))
        guard.revalidate()
    return result


def atomic_json(path, value):
    path = Path(path)
    tmp = path.with_name(path.name + '.writing')
    if tmp.exists() or tmp.is_symlink():
        raise RestoreError('중단된 메타데이터 쓰기 흔적을 확인하세요: ' + str(tmp))
    created = None
    with PathGuard(for_write=True) as guard:
        parent_fd = guard.directory(path.parent)
        owner = os.fstat(parent_fd)
        if path.exists() or path.is_symlink():
            with guard.file(path, private=True) as existing:
                owner = os.fstat(existing)
        try:
            with guard.file(tmp, private=True, create=True, flags=os.O_WRONLY) as fd:
                if os.geteuid() == 0:
                    os.fchown(fd, owner.st_uid, owner.st_gid)
                created = guard.identity(os.fstat(fd))
                os.fchmod(fd, 0o600)
                content = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
                with os.fdopen(os.dup(fd), 'wb') as stream:
                    stream.write(content)
                    stream.flush()
                os.fsync(fd)
            guard.replace(tmp, path)
            os.fsync(parent_fd)
        finally:
            if created is not None and (tmp.exists() or tmp.is_symlink()):
                guard.unlink(tmp, expected=created)


def verify_signature(app):
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', app)


def signature(app):
    return run('/usr/bin/codesign', '-dv', '--verbose=2', app).stderr.decode()


def entitlements(app):
    data = run('/usr/bin/codesign', '-d', '--entitlements', ':-', app).stdout
    try:
        value = plistlib.loads(data)
    except Exception as error:
        raise RestoreError('앱 권한 정보를 읽을 수 없습니다') from error
    if not isinstance(value, dict):
        raise RestoreError('앱 권한 정보 형식이 예상과 다릅니다')
    return value


def require_host():
    if sys.platform != 'darwin' or platform.machine() not in ('arm64', 'x86_64'):
        raise RestoreError('이 도구는 Apple Silicon 또는 Intel Mac에서 실행하세요.', 'UNSUPPORTED_HOST')


def load_json(path):
    try:
        raw = read_regular(path, private=True)
        if len(raw) > 32 * 1024 * 1024:
            raise ValueError('크기 초과')
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError('객체 아님')
        return value
    except (ValueError, UnicodeError) as error:
        raise RestoreError('기록 파일을 읽을 수 없습니다: ' + str(path), 'INVALID_RECORD') from error


def app_info(app):
    try:
        value = plistlib.loads(read_regular(app / INFO))
        if (not isinstance(value, dict) or value.get('CFBundleIdentifier') != BUNDLE_ID or
                not isinstance(value.get('CFBundleShortVersionString'), str) or
                not isinstance(value.get('CFBundleVersion'), (str, int))):
            raise ValueError('식별자 오류')
        return value
    except (ValueError, OSError, plistlib.InvalidFileException) as error:
        raise RestoreError('공식 카카오톡의 앱 식별 정보를 확인할 수 없습니다.', 'INVALID_APP') from error


def official(app):
    app_info(app)
    verify_signature(app)
    run('/usr/bin/codesign', '--verify', '--deep', '--strict',
        '--test-requirement', OFFICIAL_REQUIREMENT, app)
    lines = signature(app).splitlines()
    if ('TeamIdentifier=' + TEAM_ID not in lines or
            not any(line.startswith('Authority=Apple') for line in lines)):
        raise RestoreError('카카오의 공식 Apple 서명이 필요합니다.', 'NOT_OFFICIAL')


def user_backup_root():
    uid = os.geteuid()
    if uid == 0 and 'SUDO_UID' in os.environ:
        try:
            uid = int(os.environ['SUDO_UID'])
        except ValueError as error:
            raise RestoreError('SUDO_UID가 올바르지 않습니다.') from error
    try:
        home = pwd.getpwuid(uid).pw_dir
    except KeyError as error:
        raise RestoreError('실행 사용자의 홈 폴더를 확인할 수 없습니다.', 'INVALID_USER') from error
    return safe_path(Path(home) / 'Library/Application Support/NoAdKakaoMac/backups')


def discover_backup(app):
    root = user_backup_root()
    if not root.exists():
        return None
    with PathGuard() as guard:
        guard.directory(root, private=True)
        found = []
        for entry in sorted(root.iterdir()):
            safe_path(entry)
            if not entry.is_dir():
                continue
            meta = entry / 'manifest.json'
            if meta.exists() and load_json(meta).get('app_path') == str(app):
                found.append(entry)
    if len(found) > 1:
        raise RestoreError('이 앱의 백업이 여러 개입니다. --backup-dir로 하나를 지정하세요.', 'AMBIGUOUS_BACKUP')
    return found[0] if found else None


def identity(path):
    value = path.lstat()
    if not stat.S_ISDIR(value.st_mode):
        raise RestoreError('앱 디렉터리 형식이 다릅니다.', 'ARTIFACT_CHANGED')
    return {'dev': value.st_dev, 'ino': value.st_ino}


class Restorer:
    def __init__(self, app, backup_dir=None):
        self.app = safe_path(app)
        if self.app.suffix != '.app':
            raise RestoreError('대상은 .app 확장자의 앱 번들이어야 합니다.', 'INVALID_APP_PATH')
        self.backup_dir = safe_path(backup_dir) if backup_dir else None
        self._check_overlap()
        key = hashlib.sha256(str(self.app).encode()).hexdigest()[:16]
        stem = '.' + self.app.name + '.noadkakaomac-' + key
        self.lock = self.app.parent / (stem + '.lock')
        self.stage = self.app.parent / (stem + '.restore-stage.app')
        self.previous = self.app.parent / (stem + '.restore-previous.app')
        self.legacy = [self.app.parent / (stem + suffix) for suffix in ('.stage.app', '.previous.app')]
        self.record = None
        self._lock_active = False

    def _check_overlap(self):
        if self.backup_dir is not None and (self.backup_dir == self.app or
                self.app in self.backup_dir.parents or self.backup_dir in self.app.parents):
            raise RestoreError('앱과 백업 폴더는 서로 겹칠 수 없습니다.', 'OVERLAPPING_PATHS')

    def _select(self):
        if self.backup_dir is None:
            self.backup_dir = discover_backup(self.app)
        self._check_overlap()
        if self.backup_dir is None:
            raise RestoreError('사용 가능한 전체 원본 백업이 없습니다. 카카오톡을 공식 배포처에서 다시 설치하세요. 대화 자료는 삭제하지 마세요.', 'BACKUP_NOT_FOUND')
        if not self.backup_dir.is_dir():
            raise RestoreError('전체 원본 백업 폴더가 없습니다. 공식 배포처에서 카카오톡을 다시 설치하세요.', 'BACKUP_NOT_FOUND')
        self._check_overlap()
        self.meta = self.backup_dir / 'manifest.json'
        self.journal = self.backup_dir / 'restore-only-transaction.json'
        self.backup = self.backup_dir / 'original.app'
        with PathGuard() as guard:
            guard.directory(self.backup_dir, private=True)
        if not self.meta.exists():
            raise RestoreError('전체 원본 백업 기록이 없습니다. 카카오톡을 공식 배포처에서 다시 설치하세요.', 'BACKUP_NOT_FOUND')
        record = load_json(self.meta)
        if (type(record.get('schema')) is not int or record['schema'] != 1 or
                record.get('app_path') != str(self.app) or record.get('state') not in ('ORIGINAL', 'PATCHED') or
                not isinstance(record.get('original_tree'), dict) or not record['original_tree'] or
                not isinstance(record.get('entitlements'), dict)):
            raise RestoreError('이 앱의 schema 1 전체 백업 기록이 아닙니다.', 'INVALID_BACKUP')
        self.record = record
        self._check_original(self.backup)

    def _check_original(self, app):
        info = app_info(app)
        if (info['CFBundleShortVersionString'] != self.record.get('version') or
                str(info['CFBundleVersion']) != self.record.get('build') or
                digest(app / EXE) != self.record.get('source_sha256') or
                tree_manifest(app) != self.record['original_tree'] or
                entitlements(app) != self.record['entitlements']):
            raise RestoreError('전체 원본 백업과 기록의 버전·빌드·파일·권한이 일치하지 않습니다.', 'BACKUP_MISMATCH')
        official(app)

    def _check_modified(self, app):
        info = app_info(app)
        if (info['CFBundleShortVersionString'] != self.record['version'] or
                str(info['CFBundleVersion']) != self.record['build'] or
                not isinstance(self.record.get('patched_tree'), dict) or
                tree_manifest(app) != self.record['patched_tree']):
            raise RestoreError('현재 앱이 이 백업에 기록된 변경 앱과 다릅니다. 덮어쓰지 않습니다.', 'APP_MISMATCH')
        verify_signature(app)

    def _pending_legacy(self):
        paths = self.legacy + [self.backup_dir / name for name in
                              ('transaction.json', 'preparation.json', 'original.preparing.app',
                               'arm64.preparing', 'manifest.json.writing', 'transaction.json.writing',
                               'preparation.json.writing', 'restore-only-transaction.json.writing')]
        for path in paths:
            if path.exists() or path.is_symlink():
                raise RestoreError('이전 작업의 잔여 파일을 보존했습니다. 자동 복원할 수 없습니다: ' + str(path), 'LEGACY_OPERATION_PENDING')

    @contextlib.contextmanager
    def _observation(self):
        if self._lock_active:
            yield
            return
        if not self.lock.exists():
            yield
            if self.lock.exists():
                raise RestoreError('관측 중 다른 작업이 시작됐습니다. 다시 확인하세요.', 'OBSERVATION_CHANGED')
            return
        with PathGuard() as guard, guard.file(self.lock, private=True) as fd:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RestoreError('다른 작업이 진행 중입니다. 끝난 뒤 확인하세요.', 'BUSY') from error
            yield

    def status(self):
        with self._observation():
            return self._status()

    def _status(self):
        # 공식 앱은 이전 백업의 존재나 버전과 관계없이 그대로 둡니다.
        if self.app.exists():
            try:
                tree_manifest(self.app)
                official(self.app)
            except RestoreError:
                pass
            else:
                # 공식 앱은 유지하되, 이 도구의 미완료 기록은 숨기지 않습니다.
                try:
                    self._select_if_available()
                    if self.backup_dir is not None and (self.backup_dir / 'restore-only-transaction.json').exists():
                        self._select()
                        self._load_journal()
                        if tree_manifest(self.app) == self.record['original_tree']:
                            return {'state': 'RECOVERY_REQUIRED', 'message': '공식 앱 복원은 끝났습니다. restore를 다시 실행해 기록 정리를 마무리하세요.'}
                        return {'state': 'ORIGINAL', 'message': '공식 앱을 유지합니다. 다른 버전의 중단 기록은 보존했습니다.'}
                except (RestoreError, OSError):
                    return {'state': 'ORIGINAL', 'message': '공식 앱을 유지합니다. 이전 백업 기록은 확인하지 못했습니다.'}
                return {'state': 'ORIGINAL', 'message': '공식 서명이 유효합니다. 변경할 필요가 없습니다.'}
        self._select()
        self._pending_legacy()
        if self.journal.exists():
            self._load_journal()
            if self.stage.exists():
                try:
                    self._check_original(self.stage)
                except (RestoreError, OSError) as error:
                    raise RestoreError('준비 복사본이 불완전하거나 변경됐습니다. 파일을 보존했으며 자동 재시도할 수 없습니다. 오류 코드와 함께 문의하세요.', 'INCOMPLETE_PREPARATION') from error
            return {'state': 'RECOVERY_REQUIRED', 'message': '중단된 복원이 있습니다. restore 명령으로 이어서 복구하세요.'}
        if self.stage.exists() or self.previous.exists():
            raise RestoreError('기록에 연결되지 않은 복원 파일을 보존했습니다: ' + str(self.stage if self.stage.exists() else self.previous), 'UNKNOWN_ARTIFACT')
        self._check_modified(self.app)
        return {'state': 'RESTORABLE', 'message': '기록과 공식 전체 백업을 확인했습니다. 복원할 수 있습니다.'}

    @contextlib.contextmanager
    def _locked(self):
        with PathGuard(for_write=True) as guard:
            guard.directory(self.app.parent)
            with guard.file(self.lock, private=True, create=not self.lock.exists(), flags=os.O_RDWR) as fd:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise RestoreError('이 앱의 다른 작업이 진행 중입니다.', 'BUSY') from error
                if os.geteuid() == 0 and 'SUDO_UID' in os.environ:
                    caller = pwd.getpwuid(int(os.environ['SUDO_UID']))
                    os.fchown(fd, caller.pw_uid, caller.pw_gid)
                self._check_not_running()
                self._lock_active = True
                try:
                    yield
                finally:
                    self._lock_active = False

    def _check_not_running(self):
        output = run('/bin/ps', '-axo', 'pid=,comm=').stdout.decode(errors='replace')
        if any(len(parts := line.strip().split(None, 1)) == 2 and
               parts[1].startswith(str(self.app) + '/') for line in output.splitlines()):
            raise RestoreError('카카오톡과 보조 프로세스를 종료한 뒤 실행하세요.', 'APP_RUNNING')

    def _move(self, source, target):
        with PathGuard(for_write=True) as guard:
            guard.replace(source, target)
            os.fsync(guard.directory(target.parent))

    def _load_journal(self):
        value = load_json(self.journal)
        if (type(value.get('schema')) is not int or value.get('schema') != 1 or value.get('app_path') != str(self.app) or
                value.get('original_tree') != self.record['original_tree'] or
                value.get('patched_tree') != self.record.get('patched_tree') or
                not isinstance(value.get('stage_identity'), dict) or
                not isinstance(value.get('previous_identity'), dict)):
            raise RestoreError('복원 중단 기록이 이 백업과 다릅니다.', 'INVALID_JOURNAL')
        for key in ('stage_identity', 'previous_identity'):
            if (set(value[key]) != {'dev', 'ino'} or
                    any(type(item) is not int or item < 0 for item in value[key].values())):
                raise RestoreError('복원 중단 기록의 파일 신원이 올바르지 않습니다.', 'INVALID_JOURNAL')
        return value

    def _finish(self, journal):
        self._check_original(self.app)
        if self.previous.exists():
            if identity(self.previous) != journal['previous_identity']:
                raise RestoreError('보존한 이전 앱의 신원이 다릅니다.', 'ARTIFACT_CHANGED')
            self._check_modified(self.previous)
        self.record['state'] = 'ORIGINAL'
        atomic_json(self.meta, self.record)
        with PathGuard(for_write=True) as guard:
            guard.unlink(self.journal)
        return {'state': 'RESTORED', 'message': '공식 원본으로 복원했습니다. 전체 백업과 복원 전 앱을 보존했습니다.',
                'previous_app': str(self.previous)}

    def _resume(self):
        journal = self._load_journal()
        # 이미 공식 앱이 설치됐으면 기록만 마무리합니다.
        if self.app.exists():
            try:
                self._check_original(self.app)
            except RestoreError:
                self._check_modified(self.app)
            else:
                if self.stage.exists():
                    raise RestoreError('설치 후 준비 파일이 남아 있어 보존했습니다.', 'UNKNOWN_ARTIFACT')
                return self._finish(journal)
        if self.stage.exists():
            if identity(self.stage) != journal['stage_identity']:
                raise RestoreError('준비 파일의 신원이 변경됐습니다.', 'ARTIFACT_CHANGED')
            self._check_original(self.stage)
        else:
            raise RestoreError('검증된 준비 앱이 없습니다. 중단 파일을 보존했습니다.', 'RECOVERY_REQUIRED')
        if self.app.exists():
            if self.previous.exists() or identity(self.app) != journal['previous_identity']:
                raise RestoreError('현재 앱 또는 보존 경로가 변경됐습니다.', 'ARTIFACT_CHANGED')
            self._check_modified(self.app)
            self._check_not_running()
            self._move(self.app, self.previous)
        else:
            if not self.previous.exists() or identity(self.previous) != journal['previous_identity']:
                raise RestoreError('복원 전 앱의 위치를 확인할 수 없습니다.', 'ARTIFACT_CHANGED')
            self._check_modified(self.previous)
        try:
            self._check_not_running()
            self._move(self.stage, self.app)
        except (OSError, RestoreError):
            # 설치 경로가 비었을 때만 방금 보존한 앱을 되돌립니다.
            # 강제 중단은 저널을 남겨 다음 실행에서 공식 원본 방향으로 이어갑니다.
            if not self.app.exists() and self.previous.exists():
                if identity(self.previous) == journal['previous_identity']:
                    self._check_modified(self.previous)
                    self._move(self.previous, self.app)
            raise
        return self._finish(journal)

    def restore(self):
        require_host()
        with self._locked():
            # 자체 저널이 있다면 공식 앱 설치 후 기록 정리도 실행합니다.
            self._select_if_available()
            if self.backup_dir is not None and (self.backup_dir / 'restore-only-transaction.json').exists():
                self._select()
                self._pending_legacy()
                return self._resume()
            result = self.status()
            if result['state'] == 'ORIGINAL':
                return result
            self._check_modified(self.app)
            self._pending_legacy()
            needed = sum(item.get('size', 0) for item in self.record['original_tree'].values())
            if shutil.disk_usage(self.app.parent).free < needed + 64 * 1024 * 1024:
                raise RestoreError('전체 원본을 준비할 디스크 공간이 부족합니다.', 'NO_SPACE')
            with PathGuard(for_write=True) as guard:
                parent = guard.directory(self.app.parent)
                os.mkdir(self.stage.name, 0o700, dir_fd=parent)
            journal = {'schema': 1, 'app_path': str(self.app),
                       'original_tree': self.record['original_tree'], 'patched_tree': self.record['patched_tree'],
                       'stage_identity': identity(self.stage), 'previous_identity': identity(self.app)}
            atomic_json(self.journal, journal)
            # 불완전한 복사는 설치하지 않습니다. 중단된 준비 파일과 저널은 보존합니다.
            run('/usr/bin/ditto', '--rsrc', '--extattr', '--acl', self.backup, self.stage)
            with PathGuard(for_write=True) as guard:
                with_fd = os.open(self.stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    if identity(self.stage) != journal['stage_identity']:
                        raise RestoreError('복사 중 준비 파일이 교체됐습니다.', 'ARTIFACT_CHANGED')
                    opened = guard._check(with_fd, self.stage, directory=True)
                    if {'dev': opened.st_dev, 'ino': opened.st_ino} != journal['stage_identity']:
                        raise RestoreError('열린 준비 파일의 신원이 다릅니다.', 'ARTIFACT_CHANGED')
                    os.fchmod(with_fd, self.record['original_tree']['.']['mode'])
                finally:
                    os.close(with_fd)
            self._check_original(self.stage)
            return self._resume()

    def _select_if_available(self):
        if self.backup_dir is None:
            self.backup_dir = discover_backup(self.app)
        self._check_overlap()


def _diagnostic_version(value):
    # 앱·기록이 임의 문자열을 담더라도 제보 결과에 그대로 옮기지 않습니다.
    return value if isinstance(value, str) and re.fullmatch(r'[0-9]+(?:\.[0-9]+)*(?:-rc\.[0-9]+)?', value[:48]) and len(value) <= 48 else None


def _diagnostic_path(path):
    try:
        info = path.lstat()
        return {'exists': True, 'symlink': stat.S_ISLNK(info.st_mode),
                'mode': format(stat.S_IMODE(info.st_mode), '04o'),
                'readable': os.access(path, os.R_OK), 'writable': os.access(path, os.W_OK),
                'owned_by_current_user': info.st_uid == os.geteuid()}
    except FileNotFoundError:
        return {'exists': False}
    except OSError as error:
        return {'accessible': False, 'errno': error.errno}


def _diagnose(app, backup_dir=None):
    """공유할 값만 골라 경로와 외부 명령의 원문을 출력하지 않습니다."""
    report = {'schema': 1, 'tool_version': VERSION,
              'environment': {'macos': _diagnostic_version(platform.mac_ver()[0]),
                              'architecture': platform.machine() if platform.machine() in ('arm64', 'x86_64') else 'other',
                              'python': '.'.join(str(item) for item in sys.version_info[:3]),
                              'administrator': os.geteuid() == 0},
              'options': {'custom_app': str(app) != '/Applications/KakaoTalk.app',
                          'explicit_backup': backup_dir is not None}}
    tool = None
    try:
        require_host()
        tool = Restorer(app, backup_dir)
        result = tool.status()
        report['status'] = {'state': result['state']}
    except (RestoreError, OSError) as error:
        report['status'] = {'state': 'ERROR', 'code': getattr(error, 'code', 'IO_ERROR')}
        if isinstance(error, OSError):
            report['status']['errno'] = error.errno
    if tool is not None:
        report['app'] = _diagnostic_path(tool.app)
        try:
            info = app_info(tool.app)
            report['app']['version'] = _diagnostic_version(info['CFBundleShortVersionString'])
            report['app']['build'] = _diagnostic_version(str(info['CFBundleVersion']))
        except (RestoreError, OSError):
            pass
        report['artifacts'] = {name: _diagnostic_path(path) for name, path in
                               [('lock', tool.lock), ('stage', tool.stage), ('previous', tool.previous),
                                ('legacy_stage', tool.legacy[0]), ('legacy_previous', tool.legacy[1])]}
        backup = tool.backup_dir
        if backup is None:
            try:
                backup = discover_backup(tool.app)
            except (RestoreError, OSError):
                pass
        report['backup_selected'] = backup is not None
        if backup is not None:
            report['backup'] = {name: _diagnostic_path(backup / name) for name in
                                ('manifest.json', 'original.app', 'transaction.json', 'preparation.json',
                                 'restore-only-transaction.json', 'restore-only-transaction.json.writing')}
            try:
                record = load_json(backup / 'manifest.json')
                report['record'] = {'schema': 1 if type(record.get('schema')) is int and record['schema'] == 1 else 'other',
                                    'state': record.get('state') if record.get('state') in ('ORIGINAL', 'PATCHED') else 'other',
                                    'tool_version': _diagnostic_version(record.get('tool_version'))}
            except (RestoreError, OSError):
                pass
    return report


def diagnose(app, backup_dir=None):
    try:
        return _diagnose(app, backup_dir)
    except Exception:
        # 예상하지 못한 형식·파일 오류도 경로가 담긴 traceback으로 공개하지 않습니다.
        return {'schema': 1, 'tool_version': VERSION,
                'status': {'state': 'ERROR', 'code': 'UNEXPECTED_DIAGNOSTIC_ERROR'}}


class KoreanParser(argparse.ArgumentParser):
    def format_usage(self):
        return super().format_usage().replace('usage:', '사용법:', 1)

    def format_help(self):
        return super().format_help().replace('usage:', '사용법:', 1)

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, '오류: 명령 또는 옵션이 올바르지 않습니다. --help로 사용법을 확인하세요.\n')


def diagnostic_main(argv=None):
    parser = KoreanParser(add_help=False, description='복구 오류 제보용 읽기 전용 진단입니다. 앱과 백업을 변경하지 않으며 경로·원시 오류는 출력하지 않습니다.')
    parser._optionals.title = '옵션'
    parser.add_argument('-h', '--help', action='help', help='사용법 표시 후 종료')
    parser.add_argument('--app', default='/Applications/KakaoTalk.app', help='카카오톡 앱 경로')
    parser.add_argument('--backup-dir', help='manifest.json과 original.app이 있는 백업 폴더')
    parser.add_argument('--version', action='version', version=VERSION, help='도구 버전 표시 후 종료')
    args = parser.parse_args(argv)
    print(json.dumps(diagnose(args.app, args.backup_dir), ensure_ascii=False, indent=2))
    return 0


def main(argv=None):
    parser = KoreanParser(add_help=False, description='전체 원본 백업으로 카카오톡 공식 앱을 복원합니다. 버전 표는 사용하지 않습니다.')
    parser._positionals.title = '명령'
    parser._optionals.title = '옵션'
    parser.add_argument('-h', '--help', action='help', help='사용법 표시 후 종료')
    parser.add_argument('command', choices=('status', 'restore', 'diagnose'), nargs='?', default='status', help='상태 확인, 공식 원본 복원 또는 제보용 진단')
    parser.add_argument('--app', default='/Applications/KakaoTalk.app', help='카카오톡 앱 경로')
    parser.add_argument('--backup-dir', help='기존 manifest.json과 original.app이 있는 백업 폴더')
    parser.add_argument('--version', action='version', version=VERSION, help='도구 버전 표시 후 종료')
    args = parser.parse_args(argv)
    if args.command == 'diagnose':
        print(json.dumps(diagnose(args.app, args.backup_dir), ensure_ascii=False, indent=2))
        return 0
    try:
        require_host()
        tool = Restorer(args.app, args.backup_dir)
        result = tool.status() if args.command == 'status' else tool.restore()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (RestoreError, OSError) as error:
        print(json.dumps({'state': 'ERROR', 'code': getattr(error, 'code', 'IO_ERROR'), 'message': str(error)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
