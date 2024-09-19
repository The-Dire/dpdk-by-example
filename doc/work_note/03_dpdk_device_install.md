# dpdk 19.11增加某款网卡驱动适配

dpdk需要适配不少国产网卡，下面是通用流程

## 驱动源码获取

解压xx网卡的pmd驱动dpdk-pmd-test.zip，复制到dpdk驱动目录drivers/net中。其中test是某款网卡的驱动名称。

```shell
unzip dpdk-pmd-test.zip
ls dpdk-pmd-test.zip
# dpdk_user_document.txt  Makefile  meson.build  test  readme  scripts  VERSION
cp dpdk-pmd-test/test/19.11/* dpdk-19.11/drivers/net/test -rf
```

## 增加对应驱动编译(修改mk/rte.app.mk)

增加网卡的驱动连接

```Makefile
_LDLIBS-$(CONFIG_RTE_LIBRTE_TEST_PMD)      += -lrte_pmd_test
```
## 增加网卡驱动目录

修改drivers/net/Makefile

```Makefile
DIRS-$(CONFIG_RTE_LIBRTE_TEST_PMD) += test
```

## 增加网卡的驱动配置选项

修改config/common_base

```Makefile
#
# Compile burst-oriented TEST PMD driver
#
CONFIG_RTE_LIBRTE_TEST_PMD=y
CONFIG_RTE_LIBRTE_TEST_DEBUG_RX=n
CONFIG_RTE_LIBRTE_TEST_DEBUG_TX=n
CONFIG_RTE_LIBRTE_TEST_DEBUG_TX_FREE=n
CONFIG_RTE_TEST_INC_VECTOR=n
CONFIG_RTE_LIBRTE_TEST_BYPASS=n
CONFIG_RTE_TEST_POLL=n
CONFIG_RTE_TEST_RETRY=n
```

## 重新生成x86_64-native-linux-gcc/.config

```shell
make config T=x86_64-native-linuxapp-gcc
```
或者直接修改x86_64-native-linux-gcc/.config文件，添加common_base里新增的内容

## 编译验证

编译dpdk.

```shell
export RTE_SDK=${PWD}
export RTE_TARGET=x86_64-native-linuxapp-gcc
make -C examples/l2fwd
```


有的驱动更新后运行l2fwd时会报错，此时需要参考厂商文档添加代码：

比如我遇到过的一个驱动就需要需要在l2fwd的main.c增加cgroup配置

```c
#include <sys/types.h>
#include <unistd.h>

void  addself_global_cgroup(void);
void  addself_global_cgroup(void)
{
    char name[] = "/sys/fs/cgroup/cpuset/tasks";
    FILE* globaltask = NULL;
    globaltask = fopen(name,"a");
    int pid = getpid();
    if(globaltask)
    {
        fprintf(globaltask,"%d\n",pid);
        fclose(globaltask);
    }
}
```

将这个函数的调用放到l2fwd的main函数内部。

重新编译，利用生成的l2fwd验证，网口流量是否转发成功。
