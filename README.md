# pairwise-http-boundary

反向代理换新版本后，前后端对请求边界的理解开始不一致：同时带 Content-Length 和 Transfer-Encoding 时，代理取 CL、后端取 TE；chunk 扩展和 obs-fold 被原样转发，后端解析出额外请求；header 名大小写和空格没有归一，重复 CL 取了第一个；请求体里嵌 NUL 或超长 header 没有拒绝；代理和后端对 100-continue 的处理不同。security/http_boundary.py 是核心，tests/test_http_boundary.py 15个红。要修的是：CL/TE 冲突拒绝；chunk 严格解析；header 归一；NUL/长度限制；统一 100-continue。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
