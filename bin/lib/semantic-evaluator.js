/**
 * Semantic Evaluator for Sentinel Phase 11.
 * Discovers and assesses the quality of compliance documentation.
 */
const fs = require('fs');
const path = require('path');
const { callLLM } = require('./llm-provider');

/**
 * Evaluates a single document's quality using LLM.
 */
async function evaluateDocumentQuality(content, articleContext) {
  const systemPrompt = "You are a technical compliance analyst evaluating documentation for EU AI Act alignment. You assess whether documents are technically complete, not whether they are legally sufficient. You do not issue legal opinions. Respond only in valid JSON.";
  const userPrompt = `Evaluate this compliance document for ${articleContext} requirements.

Document content:
${content}

Respond with exactly this JSON structure:
{
  "completeness": "COMPLETE|PARTIAL|INSUFFICIENT",
  "completeness_score": 0-100,
  "present_elements": ["list of what is covered"],
  "missing_elements": ["list of what is absent"],
  "quality_indicators": {
    "has_specific_procedures": true|false,
    "has_responsible_parties": true|false,
    "has_measurable_criteria": true|false,
    "has_review_process": true|false
  },
  "summary": "one sentence technical assessment",
  "confidence": "HIGH|MEDIUM|LOW"
}`;

  try {
    const response = await callLLM(systemPrompt, userPrompt);
    if (!response) throw new Error("LLM unavailable");

    // Extract JSON if wrapped in markdown
    const jsonMatch = response.match(/\{[\s\S]*\}/);
    const result = JSON.parse(jsonMatch ? jsonMatch[0] : response);

    return {
      article: articleContext,
      completeness: result.completeness,
      completeness_score: result.completeness_score,
      present_elements: result.present_elements,
      missing_elements: result.missing_elements,
      quality_indicators: result.quality_indicators,
      summary: result.summary,
      confidence: result.confidence,
      evaluated_at: new Date().toISOString(),
      evaluation_type: "SEMANTIC_LLM",
      disclaimer: "Semantic quality indicator only. Does not constitute legal compliance assessment."
    };
  } catch (err) {
    return {
      article: articleContext,
      completeness: "UNAVAILABLE",
      completeness_score: null,
      evaluation_type: "SEMANTIC_LLM",
      error: "LLM evaluation unavailable",
      disclaimer: "Semantic evaluation was not performed. Manual review required."
    };
  }
}

/**
 * Batch evaluates all discovered documents.
 */
async function evaluateAllDocuments(docsMap) {
  const results = {};
  const articles = Object.keys(docsMap);

  for (const articleId of articles) {
    results[articleId] = await evaluateDocumentQuality(docsMap[articleId], articleId);
  }

  const values = Object.values(results).filter(r => r.completeness !== 'UNAVAILABLE');
  const totalEvaluated = values.length;
  const complete = values.filter(v => v.completeness === 'COMPLETE').length;
  const partial = values.filter(v => v.completeness === 'PARTIAL').length;
  const insufficient = values.filter(v => v.completeness === 'INSUFFICIENT').length;
  const unavailable = Object.values(results).filter(r => r.completeness === 'UNAVAILABLE').length;

  let overallQuality = "UNAVAILABLE";
  if (totalEvaluated > 0) {
    if (complete / totalEvaluated >= 0.8) overallQuality = "STRONG";
    else if (complete / totalEvaluated >= 0.5) overallQuality = "MODERATE";
    else if (insufficient > 0) overallQuality = "WEAK";
    else overallQuality = "MODERATE";
  }

  results._summary = {
    total_evaluated: totalEvaluated,
    complete,
    partial,
    insufficient,
    unavailable,
    overall_quality: overallQuality
  };

  return results;
}

/**
 * Discovers compliance documents in the repository.
 */
async function extractDocsFromRepo(repoPath, manifest) {
  const docsMap = {};
  const searchDirs = [
    path.join(repoPath, 'docs/compliance'),
    path.join(repoPath, 'compliance')
  ];

  // 1. Explicitly declared in manifest
  if (manifest.compliance_docs && Array.isArray(manifest.compliance_docs)) {
    for (const docPath of manifest.compliance_docs) {
      const fullPath = path.resolve(repoPath, docPath);
      if (fs.existsSync(fullPath)) {
        assignDocToArticle(fs.readFileSync(fullPath, 'utf8'), docsMap);
      }
    }
  }

  // 2. Standard directories
  for (const dir of searchDirs) {
    if (fs.existsSync(dir)) {
      const files = fs.readdirSync(dir);
      for (const file of files) {
        if (file.endsWith('.md') || file.endsWith('.txt')) {
          assignDocToArticle(fs.readFileSync(path.join(dir, file), 'utf8'), docsMap);
        }
      }
    }
  }

  // 3. Any .md file with keywords
  const crawl = (dir) => {
    if (dir.includes('node_modules') || dir.includes('.git')) return;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        crawl(fullPath);
      } else if (entry.isFile() && (entry.name.endsWith('.md') || entry.name.toLowerCase() === 'readme.md')) {
        const content = fs.readFileSync(fullPath, 'utf8');
        const keywords = ["transparency", "oversight", "human control", "logging", "audit trail", "risk assessment", "data governance"];
        if (keywords.some(k => content.toLowerCase().includes(k))) {
          assignDocToArticle(content, docsMap);
        }
      }
    }
  };
  
  try {
     crawl(repoPath);
  } catch (e) {}

  return docsMap;
}

function assignDocToArticle(content, docsMap) {
  const lowerContent = content.toLowerCase();
  let article = null;

  if (lowerContent.includes("transparency") || lowerContent.includes("disclosure")) article = "Article 13";
  else if (lowerContent.includes("oversight") || lowerContent.includes("human control") || lowerContent.includes("approval")) article = "Article 14";
  else if (lowerContent.includes("logging") || lowerContent.includes("audit") || lowerContent.includes("traceability")) article = "Article 20";
  else if (lowerContent.includes("risk") || lowerContent.includes("hazard") || lowerContent.includes("safety")) article = "Article 9";
  else if (lowerContent.includes("data") || lowerContent.includes("training") || lowerContent.includes("dataset")) article = "Article 10";

  if (article && !docsMap[article]) {
    docsMap[article] = content;
  }
}

/**
 * Generates semantic report structure.
 */
function generateSemanticReport(evaluationResults) {
  if (!evaluationResults || !evaluationResults._summary) return { evaluated: false };

  const articles = {};
  for (const [key, value] of Object.entries(evaluationResults)) {
    if (key.startsWith('Art.')) {
      articles[key] = {
        completeness: value.completeness,
        score: value.completeness_score,
        missing: value.missing_elements || [],
        summary: value.summary
      };
    }
  }

  const overall = evaluationResults._summary.overall_quality;
  let recommendation = "";
  if (overall === "STRONG") recommendation = "Documentation quality is sufficient for pre-audit preparation.";
  else if (overall === "MODERATE") recommendation = "Address missing elements before formal audit submission.";
  else if (overall === "WEAK") recommendation = "Significant documentation gaps detected. Manual review and completion required before any audit process.";
  else recommendation = "Semantic evaluation was not performed. Manual document review recommended.";

  return {
    semantic_quality: {
      evaluated: true,
      overall,
      articles,
      disclaimer: "Semantic quality indicators reflect document completeness analysis only. They do not constitute legal compliance assessment or certification.",
      recommendation
    }
  };
}

module.exports = {
  extractDocsFromRepo,
  evaluateAllDocuments,
  generateSemanticReport
};
