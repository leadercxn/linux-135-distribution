deb_distro=buster
DISTRO=stable
build_opts="-j 6"
build_opts="${build_opts} O=$PWD/../build"
build_opts="${build_opts} ARCH=arm"
build_opts="${build_opts} KBUILD_DEBARCH=${DEBARCH}"
build_opts="${build_opts} LOCALVERSION=-stm32-r1"
build_opts="${build_opts} KDEB_CHANGELOG_DIST=${deb_distro}"
build_opts="${build_opts} KDEB_PKGVERSION=1${DISTRO}"
	
build_opts="${build_opts} KDEB_SOURCENAME=linux-upstream"
make ${build_opts}  stm32mp135_seeed_defconfig
#make ${build_opts}  menuconfig
make ${build_opts}  
make ${build_opts}  bindeb-pkg
#make ${build_opts}  deb-pkg
