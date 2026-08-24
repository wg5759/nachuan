"""运行期数据文件包（catalog / store runtime profile）。

代码经 PROJECT_ROOT 相对路径读取本目录下的 models.yaml 与
store-runtime-profile.v1.json；打包安装后 PROJECT_ROOT 指向 site-packages，
因此 config 必须作为包随轮携带（ADR-0013 pip 分发）。
"""
