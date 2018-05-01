
../scripts/config --set-val CONFIG_LOG_BUF_SHIFT 17
../scripts/config --set-val CONFIG_LOG_CPU_MAX_BUF_SHIFT 15
../scripts/config --set-val CONFIG_PRINTK_SAFE_LOG_BUF_SHIFT 16

../scripts/config -e CONFIG_DEBUG_KMEMLEAK
../scripts/config -e CONFIG_DEBUG_KMEMLEAK_TEST
../scripts/config -e CONFIG_DMA_API_DEBUG
