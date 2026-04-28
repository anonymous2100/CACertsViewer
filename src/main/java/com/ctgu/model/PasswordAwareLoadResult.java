package com.ctgu.model;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 密码感知加载结果实体
 * @date 2026-04-10 14:05
 */
public record PasswordAwareLoadResult(TrustStoreDocument document, String detectedType)
{
}
