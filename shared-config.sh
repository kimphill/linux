
../scripts/config --set-val CONFIG_LOG_BUF_SHIFT 17
../scripts/config --set-val CONFIG_LOG_CPU_MAX_BUF_SHIFT 15
../scripts/config --set-val CONFIG_PRINTK_SAFE_LOG_BUF_SHIFT 16

../scripts/config -e CONFIG_DEBUG_KMEMLEAK
../scripts/config -e CONFIG_DEBUG_KMEMLEAK_TEST
../scripts/config -e CONFIG_DMA_API_DEBUG

../scripts/config -e CONFIG_DYNAMIC_DEBUG


#coresight
../scripts/config -e CONFIG_STM
../scripts/config -e CONFIG_CORESIGHT
#dunno, putting all in:
../scripts/config -e CONFIG_CORESIGHT_LINK_AND_SINK_TMC
../scripts/config -e CONFIG_CORESIGHT_SINK_TPIU
../scripts/config -e CONFIG_CORESIGHT_SINK_ETBV10
../scripts/config -e CONFIG_CORESIGHT_LINKS_AND_SINKS
../scripts/config -e CONFIG_CORESIGHT_SOURCE_ETM3X
../scripts/config -e CONFIG_CORESIGHT_SOURCE_ETM4X
#../scripts/config -e CONFIG_CORESIGHT_QCOM_REPLICATOR
../scripts/config -e CONFIG_CORESIGHT_DYNAMIC_REPLICATOR
../scripts/config -m CONFIG_CORESIGHT_STM
../scripts/config -m CONFIG_CORESIGHT_CPU_DEBUG


