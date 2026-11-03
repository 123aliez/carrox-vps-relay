这些配置仅用于 CI 冒烟和 golden 测试。
xray.json 中的 UUID 是重复数字组成的测试身份，X25519 私钥由 32 个 0x11 字节构造，shortId 为 0123456789abcdef。
这些公开测试值不能用于部署；正式密钥由 crypto/rand 和 crypto/ecdh 在受限目录中生成。
