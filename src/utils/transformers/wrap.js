/**
 * Shiki transformer that enables wrapping when `wrap` meta is present.
 */
export const transformerWrap = () => ({
  pre(node) {
    const raw = this.options.meta?.__raw?.split(" ");
    if (!raw) return;

    if (!raw.includes("wrap")) return;
    this.addClassToHast(node, "code-wrap");
  },
});
