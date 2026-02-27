/**
 * Shiki transformer that adds captions to code blocks.
 *
 * Usage:
 *  ```js caption="Bottom caption"
 *  ```js captionTop="Top caption"
 */
export const transformerCaption = () => ({
  pre(node) {
    const rawMeta = this.options.meta?.__raw;
    if (!rawMeta) return;

    const getMetaValue = key => {
      const match = rawMeta.match(
        new RegExp(`\\b${key}=("[^"]*"|'[^']*'|\\S+)`)
      );
      if (!match) return null;
      return match[1].replace(/["'`]/g, "");
    };

    const captionTop =
      getMetaValue("captionTop") ?? getMetaValue("caption-top");
    const captionBottom = getMetaValue("caption");
    const caption = captionTop || captionBottom;

    if (!caption) return;

    node.properties = node.properties || {};
    node.properties["data-caption"] = caption;
    node.properties["data-caption-position"] = captionTop ? "top" : "bottom";
  },
});
