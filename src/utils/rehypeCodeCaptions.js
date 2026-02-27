import { visit } from "unist-util-visit";

const rehypeCodeCaptions = () => tree => {
  visit(tree, "element", (node, index, parent) => {
    if (!parent || node.tagName !== "pre") return;

    const caption = node.properties?.["data-caption"];
    if (!caption) return;

    const position = node.properties?.["data-caption-position"] || "bottom";
    const isTop = position === "top";

    const wrapper = {
      type: "element",
      tagName: "div",
      properties: { className: ["code-block"] },
      children: [],
    };

    const captionNode = {
      type: "element",
      tagName: "div",
      properties: {
        className: [
          "code-caption",
          isTop ? "code-caption--top" : "code-caption--bottom",
        ],
      },
      children: [{ type: "text", value: caption }],
    };

    if (isTop) {
      wrapper.children.push(captionNode, node);
    } else {
      wrapper.children.push(node, captionNode);
    }

    parent.children[index] = wrapper;
  });
};

export default rehypeCodeCaptions;
