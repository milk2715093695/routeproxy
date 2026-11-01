# 第三方声明

routeproxy 源代码采用 Apache License 2.0，完整文本见 [LICENSE](LICENSE)。

## gfw-pac

- 来源：<https://github.com/zhiyi7/gfw-pac>
- 版权与许可：Apache License 2.0，许可文本见
  <https://www.apache.org/licenses/LICENSE-2.0>
- 本项目关系：`rules.toml` 的初始 seed、规则字段与域名/CIDR/private 决策顺序
  源自 `gfw-pac`，并与 `pacproxy` 的实现保持同源。路由决策在 Rust 中重写；
  规则快照格式和运行时实现是独立实现。
- 修改说明：本项目不包含 `gfw-pac` 源码；仅使用其规则数据与决策语义。
  部署方可替换 `rules.toml`，替换后的规则数据由部署方自行负责。

## CIDR 数据：Loyalsoldier/geoip

`rules.toml` 中的 CIDR seed 直接来自 `gfw-pac` 的 `cidrs-cn.txt`；`gfw-pac`
每周从 [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) 的
`text/cn.txt` 同步该文件。

- 来源：<https://github.com/Loyalsoldier/geoip>
- 版权与许可：**Creative Commons Attribution-ShareAlike 4.0 International
  (CC-BY-SA-4.0)**。
- 许可文本：<https://creativecommons.org/licenses/by-sa/4.0/legalcode>
  本项目随包附带完整文本：[LICENSE-DATA](LICENSE-DATA)。
- 上游数据说明：`Loyalsoldier/geoip` 默认使用 MaxMind GeoLite2 Country CSV
  数据；中国大陆 IPv4/IPv6 地址使用
  [gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip)
  （MIT License，版权行 `Copyright (c) 2017 Yifan Gao`）。具体上游数据集及其
  条款以 `Loyalsoldier/geoip` 的说明为准。
- `china-operator-ip` MIT 许可全文：

```text
MIT License

Copyright (c) 2017 Yifan Gao

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
- 本项目修改：从 `cidrs-cn.txt` 提取 CIDR 列表，转换为 TOML 数组，去重后
  与其他规则合并为 `rules.toml`；未修改单个 CIDR 的地址范围。
- 免责声明：CIDR 数据按“原样”提供，不保证完整、准确或适用于特定用途；
  使用风险由使用者承担。

CC-BY-SA-4.0 要求署名、提供许可链接、说明修改并以相同许可共享数据部分。
本文件、`NOTICE`、`README.md` 的“来源与许可”段和 `LICENSE-DATA` 用于满足
这些要求。`rules.toml` 作为生成的数据文件适用 CC-BY-SA-4.0；routeproxy 的
Rust 源代码单独适用 Apache License 2.0。
