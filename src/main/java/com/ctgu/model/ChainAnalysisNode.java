package com.ctgu.model;

import java.util.List;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 链分析结果节点实体
 * @date 2026-04-10 14:02
 */
public record ChainAnalysisNode(String alias, String subject, String role, List<String> badges)
{
}