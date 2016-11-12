#
# Spec file for package ecryptfs-simple
#
# Copyright © 2016 Francis Banyikwa <mhogomchungu@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

Name:           ecryptfs-simple
Version:        2016
Release:        0
Summary:        ecryptfs-simple is CLI front end to ecryptfs that works normal normal user account.
License:        GPL-2.0
Group:          Productivity/Security
Source:         %{name}-%{version}.tar.xz
Source100:      ecryptfs-simple-rpmlint
URL:            http://mhogomchungu.github.io/ecryptfs-simple

BuildRequires: cmake
BuildRequires: gcc
BuildRequires: glibc-devel
BuildRequires: libmount-devel
BuildRequires: libgcrypt-devel
BuildRequires: ecryptfs-utils-devel

%description
ecryptfs-simple is CLI front end to ecryptfs that works normal normal user account.

%prep
%setup -q

%build
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=RELEASE ..

%install
cd build
make DESTDIR=$RPM_BUILD_ROOT install

%post
chmod 4755 %{_bindir}/ecryptfs-simple

%clean
rm -rf %{buildroot}
rm -rf $RPM_BUILD_DIR/ecryptfs-simple

%files
%defattr(0755,root,root)
%{_bindir}/ecryptfs-simple

%changelog
