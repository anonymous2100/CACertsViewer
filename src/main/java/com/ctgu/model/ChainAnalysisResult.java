package com.ctgu.model;

import java.util.List;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 链分析结果实体
 * @date 2026-04-10 14:03
 */
public record ChainAnalysisResult(boolean trustedDirectly, boolean selfSigned, boolean certificateAuthority, boolean chainBuildComplete,
                                  boolean missingIssuer, String trustAnchorAlias, List<String> chainSubjects, List<String> diagnostics,
                                  List<ChainAnalysisNode> nodes)
{
}