#make -j 8 clean mrproper   # only the source directory  # yeah ft it still rebuilds everyting anyway
#this looks like it does a good job when messing with Kconfig though:
#make O=tc2 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- clean mrproper
rm -r tc2/drivers/hwtracing/coresight
#rm tc2/drivers/hwtracing/coresight/*.mod.*
#rm tc2/drivers/hwtracing/coresight/modules*
touch drivers/hwtracing/coresight/*

export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-

mkdir -p tc2
make O=tc2 vexpress_defconfig
cd tc2
sed -i 's/=m/=n/g' .config   # other modules are just target /lib/modules disk space polluters.

../scripts/config -e CONFIG_MODULE_FORCE_LOAD
../scripts/config -e CONFIG_MODULE_FORCE_LOAD
../scripts/config -e CONFIG_MODULE_UNLOAD
../scripts/config -e CONFIG_MODULE_FORCE_UNLOAD
../scripts/config -e CONFIG_MODVERSIONS
../scripts/config -e CONFIG_MODULE_SRCVERSION_ALL

../scripts/config -e CONFIG_EVENT_TRACING
../scripts/config -e CONFIG_FTRACE
../scripts/config -e CONFIG_FUNCTION_TRACER
../scripts/config -e CONFIG_TRACING
../scripts/config -e CONFIG_TRACING_SUPPORT
../scripts/config -e CONFIG_TRACING_EVENTS_GPIO
../scripts/config -e CONFIG_FTRACE_SYSCALLS            # for tests to find syscalls/ in debugfs

../scripts/config -m CONFIG_XFS_FS
../scripts/config -d CONFIG_DRM            # builds nouveau otherwise...who does this? just becuase we have PCI=m?
../scripts/config -d CONFIG_SOUND         # saves build time
../scripts/config -d CONFIG_CRYPTO         # saves build time
../scripts/config -d CONFIG_CRYPTO_HW         # saves build time
../scripts/config -d CONFIG_ASYMMETRIC_KEY_TYPE         # saves build time
../scripts/config -d CONFIG_BT            # saves build time
../scripts/config -d CONFIG_BLK_DEV_MD            # saves build time
../scripts/config -d CONFIG_ARCH_TEGRA
../scripts/config -d CONFIG_CONFIG_RAID6_PQ
../scripts/config -d CONFIG_INTEGRITY
../scripts/config -d CONFIG_XEN
../scripts/config -d CONFIG_NET_9P
../scripts/config -d CONFIG_9P_FS
../scripts/config -d CONFIG_WLAN
../scripts/config -d CONFIG_WIRELESS
../scripts/config -d CONFIG_WIRELESS_EXT
../scripts/config -d CONFIG_IPV6
../scripts/config -d CONFIG_FB
../scripts/config -d CONFIG_VIDEO_V4L2
../scripts/config -d CONFIG_CONFIG_VIDEO_DEV
../scripts/config -d CONFIG_LOGO
../scripts/config -d CONFIG_VIRTUALIZATION

../scripts/config -d CONFIG_ARM_SMMU    # maybe fix not mounting rootfs (no sata driver) on tc2 problem 4.12-rc4
../scripts/config -d CONFIG_ARM_SMMU_V3 # ditto

#this bugger is default m and just gets in my eyes' way:
../scripts/config -u PNFS_FLEXFILE_LAYOUT
../scripts/config -u PNFS_BLOCK
../scripts/config -u PNFS_FILE_LAYOUT
# ok one or both of these  two actually did the trick:
../scripts/config -u NFS_V4_1 
../scripts/config -u NFS_V3

#from model makearm64:
#OK FOR SOME REASON THESE MAKE dev containing debian rootfs not mount (fail to find rootfs):
#yep, verified once more:
#[    4.358189] Waiting for root device PARTUUID=99389c0e-3d5a-4d98-b970-c0deb747...
#[   85.538662] random: crng init done
#get above if uncomment the following chunk:
#../scripts/config -d CONFIG_E1000E
#../scripts/config -d CONFIG_IGB
#../scripts/config -d CONFIG_IGBVF
#../scripts/config -d CONFIG_SKY2
#../scripts/config -d CONFIG_VFIO
#../scripts/config -d CONFIG_PCI
#../scripts/config -d CONFIG_KVM
#../scripts/config -d CONFIG_EXT4_ENCRYPTION
#../scripts/config -d CONFIG_RXKAD
#../scripts/config -d CONFIG_SERIAL_8250_FINTEK
#../scripts/config -d CONFIG_ARCH_MVEBU  # ../drivers/irqchip/irq-mvebu-odmi.c:152:15: error: variable ‘odmi_msi_ops’ has initializer but incomplete type

#coresight
../scripts/config -m CONFIG_CORESIGHT
#dunno, putting all in:
../scripts/config -m CONFIG_CORESIGHT_LINK_AND_SINK_TMC
../scripts/config -m CONFIG_CORESIGHT_SINK_TPIU
../scripts/config -m CONFIG_CORESIGHT_SINK_ETBV10
../scripts/config -m CONFIG_CORESIGHT_LINKS_AND_SINKS
../scripts/config -m CONFIG_CORESIGHT_SOURCE_ETM3X
../scripts/config -m CONFIG_CORESIGHT_SOURCE_ETM4X
#../scripts/config -e CONFIG_CORESIGHT_QCOM_REPLICATOR
../scripts/config -m CONFIG_CORESIGHT_DYNAMIC_REPLICATOR
../scripts/config -m CONFIG_CORESIGHT_STM
../scripts/config -m CONFIG_CORESIGHT_CPU_DEBUG

../scripts/config -m CONFIG_ARM_SPE_PMU

cd ..
echo CONFIG_CACHE_L2X0_PMU=y >> tc2/.config
echo CONFIG_PATA_PLATFORM=y >> tc2/.config
echo CONFIG_PATA_OF_PLATFORM=y >> tc2/.config
make O=tc2 olddefconfig

#time make O=tc2 LOADADDR=80008000 -j 8 dtbs
#time make O=tc2 LOADADDR=80008000 -j 8 
#time make O=tc2 LOADADDR=80008000 -j 8 uImage
time make O=tc2 LOADADDR=80008000 -j 8 || exit
time make O=tc2 LOADADDR=80008000 -j 8 uImage || exit
#cant have a trailing  |& tee -a make.log above (exit wont exit)
banner "make ok"
time make O=tc2 LOADADDR=80008000 -j 8  modules || exit
banner "mods ok"
time make O=tc2 LOADADDR=80008000 -j 8 dtbs || exit
banner "dtbs ok"
make --no-print-directory O=tc2 kernelrelease # run once prior to avoid 'GEN ./Makefile scripts/kconfig/conf --silentoldconfig Kconfig 4.8.0-rc2-dirty'
make --no-print-directory O=tc2 kernelrelease # run two times
export UNAMER=`make --no-print-directory O=tc2 kernelrelease`
echo kernelrelease, IMO, is $UNAMER
mkdir -p tc2/modules-install/$UNAMER
#INSTALL_MOD_PATH is relative to tc2/
time make O=tc2 -j 8 INSTALL_MOD_PATH=modules-install/$UNAMER modules_install || exit
#scp tc2/vmlinux tc2/arch/arm64/boot/Image tc2/arch/arm64/boot/dts/arm/*dtb ntel:
#echo put Image and dtbs on ntel: so, on ntel, you can plug in the firmware usb
#echo storage cable, and:
#echo sudo mount /dev/sdb1 /mnt/tmp	\# make sure it got mounted there by checking dmesg first
#echo sudo cp tc2\*dtb board\*dtb Image /mnt/tmp/SOFTWARE\; sync\; sudo sync
#echo sudo umount /mnt/tmp
echo NOT!!!!!!!!!!! going to:  ssh kim@tc2 mkdir -p /lib/modules/$UNAMER
exit
ssh kim@tc2.austin.arm.com mkdir -p /lib/modules/$UNAMER
#scp -r tc2/modules-install/$UNAMER/lib/modules/$UNAMER/{modules,kernel}* kim@192.168.1.4:/lib/modules/$UNAMER
#rsync -av --rsh=ssh --quiet tc2/modules-install/$UNAMER/lib/modules/$UNAMER/{modules,kernel}* kim@tc2:/lib/modules/$UNAMER
rsync -av --rsh=ssh tc2/modules-install/$UNAMER/lib/modules/$UNAMER/{modules,kernel}* kim@tc2:/lib/modules/$UNAMER
#cd tc2
#time make C=2 CF="-D__CHECK_ENDIAN__" -C ../tools/perf |& tee -a make-perf.log
#cd ..
#following if in cube:
#scp tc2/arch/arm64/boot/Image tc2/arch/arm64/boot/dts/arm/*dtb kimphi01@192.168.2.2:/media/kimphi01/JUNO/SOFTWARE/
#exit
#scp tc2/arch/arm64/boot/Image tc2/arch/arm64/boot/dts/arm/*dtb kim@192.168.1.4:/boottc2/SOFTWARE/
# my tc2's fw looks for a board.dtb:
cp tc2/arch/arm64/boot/dts/arm/tc2-r2.dtb tc2/arch/arm64/boot/dts/arm/board.dtb
scp tc2/arch/arm64/boot/Image tc2/arch/arm64/boot/dts/arm/board.dtb tc2/vmlinux kim@tc2.austin.arm.com:    # 192.168.1.4:
#echo copied Image and dtbs to home in case /boottc2/ failed. Copy them on-board if so with:
echo ---------------OR----------------
echo On kim@tc2, copy Image and dtb with:
echo "sudo cp /home/kim/Image /home/kim/board.dtb /boottc2/SOFTWARE/ ; sudo sync; sudo sync; sudo cp /home/kim/vmlinux /boot/vmlinux"
exit
NM, doing local:
# board's self-boot mmc storage
# /dev/sdb1: SEC_TYPE="msdos" LABEL="JUNO" UUID="A263-F758" TYPE="vfat"
UUID=A263-F758 /boottc2            vfat    defaults              0       1

