export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-
make mrproper
mkdir -p arm32
make O=arm32 mrproper
#make O=arm32 LOADADDR=80008000 multi_v7_defconfig
#make O=arm32 LOADADDR=80008000 imx_v6_v7_defconfig
#make O=arm32 LOADADDR=80008000 vexpress_defconfig
make O=arm32 LOADADDR=80008000 netwinder_defconfig
make O=arm32 olddefconfig
#echo CONFIG_CACHE_L2X0_PMU=y >> arm32/.config
#echo CONFIG_PATA_PLATFORM=y >> arm32/.config
#echo CONFIG_PATA_OF_PLATFORM=y >> arm32/.config
#echo CONFIG_PERF_EVENTS=y >> arm32/.config
#echo CONFIG_ARM_CCN=y >> arm32/.config
#time make O=arm32 LOADADDR=80008000 -j 8 dtbs
cd arm32
../scripts/config -e CONFIG_CORESIGHT
../scripts/config -e CONFIG_CORESIGHT_LINK_AND_SINK_TMC
../scripts/config -e CONFIG_CORESIGHT_SINK_TPIU
../scripts/config -e CONFIG_CORESIGHT_SINK_ETBV10
../scripts/config -e CONFIG_CORESIGHT_LINKS_AND_SINKS
../scripts/config -e CONFIG_CORESIGHT_SOURCE_ETM3X
../scripts/config -e CONFIG_CORESIGHT_SOURCE_ETM4X
../scripts/config -e CONFIG_CORESIGHT_DYNAMIC_REPLICATOR
../scripts/config -e CONFIG_CORESIGHT_STM
../scripts/config -e CONFIG_CORESIGHT_CPU_DEBUG
cd ..
make O=arm32 olddefconfig
time make O=arm32 LOADADDR=80008000 -j 8 
#time make O=arm32 LOADADDR=80008000 -j 8 uImage

exit
Generate dwarf4 debuginfo??
sudo cp arm32/arch/arm/boot/zImage /media/kim/76f979eb-c558-4478-a1c1-6672861020de/
sudo cp arm32/arch/arm/boot/dts/vexpress*.dtb /media/kim/76f979eb-c558-4478-a1c1-6672861020de/
