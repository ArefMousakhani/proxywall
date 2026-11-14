#!/bin/sh
# Builds dist/proxywall_<version>_all.deb. Needs only dpkg-deb; no root.
#
#   packaging/build-deb.sh            (DEB_MAINTAINER and HOMEPAGE can be overridden from the environment)
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
version=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$root/proxywall/__init__.py")
maintainer=${DEB_MAINTAINER:-Aref Mousakhani <ArefMousakhani@users.noreply.github.com>}
homepage=${HOMEPAGE:-https://github.com/ArefMousakhani/proxywall}
out=${1:-$root/dist}

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
pkg=$stage/proxywall
umask 022

install -d "$pkg/DEBIAN" "$pkg/usr/bin" "$pkg/usr/lib/proxywall/proxywall/gui" \
    "$pkg/usr/lib/systemd/system" "$pkg/usr/share/applications" \
    "$pkg/usr/share/icons/hicolor/scalable/apps" "$pkg/usr/share/proxywall/icons" \
    "$pkg/usr/share/doc/proxywall"

install -m 644 "$root"/proxywall/*.py "$pkg/usr/lib/proxywall/proxywall/"
install -m 644 "$root"/proxywall/gui/*.py "$root"/proxywall/gui/style.css "$pkg/usr/lib/proxywall/proxywall/gui/"
install -m 755 "$here/bin/proxywalld" "$pkg/usr/lib/proxywall/proxywalld"
install -m 755 "$here/bin/proxywall" "$here/bin/proxywall-gui" "$pkg/usr/bin/"
install -m 644 "$root/data/proxywall.service" "$pkg/usr/lib/systemd/system/"
install -m 644 "$root/data/io.github.proxywall.ProxyWall.desktop" "$pkg/usr/share/applications/"
install -m 644 "$root/data/icons/proxywall.svg" "$pkg/usr/share/icons/hicolor/scalable/apps/"
install -m 644 "$root"/data/icons/*.svg "$pkg/usr/share/proxywall/icons/"
install -m 644 "$root/README.md" "$root"/docs/*.md "$pkg/usr/share/doc/proxywall/"
install -m 644 "$here/debian/copyright" "$pkg/usr/share/doc/proxywall/copyright"
gzip -9n -c "$root/CHANGELOG.md" > "$pkg/usr/share/doc/proxywall/changelog.gz"

size=$(du -sk --exclude=DEBIAN "$pkg" | cut -f1)
sed -e "s|@VERSION@|$version|" -e "s|@MAINTAINER@|$maintainer|" \
    -e "s|@SIZE@|$size|" -e "s|@HOMEPAGE@|$homepage|" \
    "$here/debian/control.in" > "$pkg/DEBIAN/control"
install -m 755 "$here/debian/postinst" "$here/debian/prerm" "$here/debian/postrm" "$pkg/DEBIAN/"
(cd "$pkg" && find usr -type f -exec md5sum {} + | sort -k2) > "$pkg/DEBIAN/md5sums"

mkdir -p "$out"
deb=$out/proxywall_${version}_all.deb
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$deb" >/dev/null
echo "$deb"
