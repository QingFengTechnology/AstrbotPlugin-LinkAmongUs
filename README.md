# Login with Among Us

![AstrbotPlugin-LinkAmongUs](https://socialify.git.ci/QingFengTechnology/AstrbotPlugin-LinkAmongUs/image?description=1&font=KoHo&language=1&name=1&pattern=Solid&theme=Auto)

本插件旨在提供一个方法允许玩家使用他的 Among Us 账号与 QQ 号进行关联（写入插件的数据库），以达到防止机器人等的目的。

## 前置

- Astrbot 4.5.0+
- Nmpostor 1.0.15+
- MySQL 8.x

> [!Note]
> 此处的 Nmpostor 指 [Impostor NikoCat233 Edition](https://au.niko233.me/cn.html)，并非开源的 Impostor 哦。\
> 由于 Impostor 没有我们所需的 API，因此我们不会考虑对 Impostor 进行适配。

## 安装

在 Astrbot WebUI 插件页面点击`安装`按钮，选择`从链接安装`，复制粘贴本仓库 URL 并点击安装即可。

> [!important]
> 此插件仅适用于 aiocqhttp 平台，其余平台发来的请求插件将不会响应。

## 使用

安装插件后，在你的服务器上新建用于此插件的数据库，随后将连接信息填入插件配置。

> [!Warning]
> 此处填写的密码不会被加密处理，因此不建议使用 root 用户。

随后根据自身需求填写剩下的配置，保存并重载即可。\
要查看插件命令帮助，请发送`/verify help`命令。