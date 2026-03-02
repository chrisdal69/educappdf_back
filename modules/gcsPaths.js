const getGcsEnvFolder = (nodeEnv = process.env.NODE_ENV) => {
  const override =
    typeof process.env.GCS_ENV_FOLDER === "string"
      ? process.env.GCS_ENV_FOLDER.trim()
      : "";
  if (override) return override;
  return nodeEnv === "production" ? "eap" : "eap-test";
};

const normalizeSegment = (value) => {
  if (typeof value !== "string" && typeof value !== "number") return "";
  return `${value}`.replace(/^\/+|\/+$/g, "");
};

const joinGcsPath = (...segments) => {
  const cleaned = segments.map(normalizeSegment).filter(Boolean);
  return cleaned.join("/");
};

const buildCardPrefix = ({ nodeEnv, gcsEnvFolder, classe, repertoire, tagNumber }) => {
  const envFolder = gcsEnvFolder || getGcsEnvFolder(nodeEnv);
  const tagSegment =
    typeof tagNumber === "number" || typeof tagNumber === "string"
      ? `tag${tagNumber}`
      : "";
  const prefix = joinGcsPath(envFolder, classe, repertoire, tagSegment);
  return prefix ? `${prefix}/` : "";
};

module.exports = {
  getGcsEnvFolder,
  joinGcsPath,
  buildCardPrefix,
};

