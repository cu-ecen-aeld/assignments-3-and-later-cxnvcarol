#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.15.163
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    # Done: Add your kernel build steps here
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} mrproper
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig
    make ARCH=${ARCH} -j 16 CROSS_COMPILE=${CROSS_COMPILE} all
#    make ARCH=${ARCH} -j 16 CROSS_COMPILE=${CROSS_COMPILE} dtbs

fi

echo "Adding the Image in outdir"
# here was a todo missing.
cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}/.

echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

# Done: Create necessary base directories
mkdir -p ${OUTDIR}/rootfs
cd ${OUTDIR}/rootfs
mkdir -p bin dev etc home lib lib64 proc sbin sys tmp usr var
mkdir -p usr/bin usr/lib usr/sbin var/log


cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
    # Done:  Configure busybox
    make distclean
    make defconfig
else
    cd busybox
fi
echo $PWD
# Done: Make and install busybox
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
make CONFIG_PREFIX=${OUTDIR}/rootfs ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install
cd ${OUTDIR}/rootfs
echo "Library dependencies"
${CROSS_COMPILE}readelf -a bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a bin/busybox | grep "Shared library"

# Done: Add library dependencies to rootfs
TOOLCHAIN_SYSROOT=$(${CROSS_COMPILE}gcc -print-sysroot)
echo "Copying from toolchain sysroot at $TOOLCHAIN_SYSROOT ..."
cp -a $TOOLCHAIN_SYSROOT/lib/ld-linux-aarch64.so.1 lib
cp -a $TOOLCHAIN_SYSROOT/lib64/libm.so.6 lib64
cp -a $TOOLCHAIN_SYSROOT/lib64/libresolv.so.2 lib64
cp -a $TOOLCHAIN_SYSROOT/lib64/libc.so.6 lib64

# Done: Make device nodes
sudo mknod -m 666 dev/null c 1 3
sudo mknod -m 600 dev/console c 5 1

# Done: Clean and build the writer utility
cd $FINDER_APP_DIR
make clean
make CROSS_COMPILE=$CROSS_COMPILE

# Done: Copy the finder related scripts and executables to the /home directory
# on the target rootfs
cp finder* ${OUTDIR}/rootfs/home/.
cp writer ${OUTDIR}/rootfs/home/.
cp -r ../conf ${OUTDIR}/rootfs/home/conf
cp autorun-qemu.sh ${OUTDIR}/rootfs/home/.

# TODO: Chown the root directory //@authors, I'm assuming chown it to the root user? (I wish you were'nt this vague.)
cd ${OUTDIR}
#chown -R root:root rootfs
## I wonder if chown for rootfs was necessary if the compressed is chowned anyway

# Done: Create initramfs.cpio.gz
cd rootfs
find . | cpio -H newc -ov --owner root:root > ../initramfs.cpio
cd ..
gzip -f initramfs.cpio

