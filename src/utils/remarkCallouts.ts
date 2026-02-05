import { visit } from "unist-util-visit";

const iconMap = {
  note: "💡",
  tip: "✨",
  info: "ℹ️",
  warning: "⚠️",
} as const;

type CalloutType = keyof typeof iconMap;

type DirectiveNode = {
  type: "containerDirective";
  name: string;
  label?: string;
  data?: {
    hName?: string;
    hProperties?: Record<string, unknown>;
  };
  children: unknown[];
};

const getParagraphText = (node: any) => {
  if (!node || node.type !== "paragraph" || !Array.isArray(node.children)) {
    return null;
  }

  if (!node.children.every((child: any) => child.type === "text")) {
    return null;
  }

  return node.children.map((child: any) => child.value).join("");
};

const buildHeadingNode = (title: string, icon: string) => ({
  type: "paragraph",
  data: {
    hName: "div",
    hProperties: { className: ["admonition-heading"] },
  },
  children: [
    { type: "text", value: `${icon} ` },
    { type: "strong", children: [{ type: "text", value: title }] },
  ],
});

const isCalloutType = (value: string): value is CalloutType => value in iconMap;

const remarkCallouts = () => (tree: unknown) => {
  visit(tree as Record<string, unknown>, (node: any) => {
    if (node.type !== "containerDirective") return;
    const directive = node as DirectiveNode;
    if (!isCalloutType(directive.name)) return;

    const data = directive.data ?? (directive.data = {});
    data.hName = "div";
    data.hProperties = {
      className: ["admonition", `admonition-${directive.name}`],
    };

    let children = directive.children;
    let title = directive.label?.trim();

    if (!title) {
      const paragraphText = getParagraphText(children[0]);
      if (paragraphText) {
        title = paragraphText.trim();
        children = children.slice(1);
      }
    } else {
      const paragraphText = getParagraphText(children[0]);
      if (paragraphText && paragraphText.trim() === title) {
        children = children.slice(1);
      }
    }

    directive.children = children;
    const finalTitle = title || directive.name;
    const headingNode = buildHeadingNode(finalTitle, iconMap[directive.name]);
    directive.children = [headingNode, ...directive.children];
  });
};

export default remarkCallouts;
