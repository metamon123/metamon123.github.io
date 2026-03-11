import { defineConfig, envField, fontProviders } from "astro/config";
import mdx from "@astrojs/mdx";
import tailwindcss from "@tailwindcss/vite";
import sitemap from "@astrojs/sitemap";
import remarkToc from "remark-toc";
import remarkCollapse from "remark-collapse";
import remarkDirective from "remark-directive";
import remarkCallouts from "./src/utils/remarkCallouts";
import rehypeCodeCaptions from "./src/utils/rehypeCodeCaptions";
import {
  transformerNotationDiff,
  transformerNotationHighlight,
  transformerNotationWordHighlight,
} from "@shikijs/transformers";
import { transformerCaption } from "./src/utils/transformers/caption";
import { transformerFileName } from "./src/utils/transformers/fileName";
import { transformerWrap } from "./src/utils/transformers/wrap";
import { SITE } from "./src/config";

// https://astro.build/config
export default defineConfig({
  site: SITE.website,
  base: "/",
  integrations: [
    mdx(),
    sitemap({
      filter: page => SITE.showArchives || !page.endsWith("/archives"),
    }),
  ],
  markdown: {
    remarkPlugins: [
      remarkToc,
      [remarkCollapse, { test: "Table of contents" }],
      remarkDirective,
      remarkCallouts,
    ],
    rehypePlugins: [rehypeCodeCaptions],
    shikiConfig: {
      // For more themes, visit https://shiki.style/themes
      themes: { light: "min-light", dark: "night-owl" },
      defaultColor: false,
      wrap: false,
      transformers: [
        transformerCaption(),
        transformerFileName({ style: "v2", hideDot: false }),
        transformerWrap(),
        transformerNotationHighlight(),
        transformerNotationWordHighlight(),
        transformerNotationDiff({ matchAlgorithm: "v3" }),
      ],
    },
  },
  vite: {
    // eslint-disable-next-line
    // @ts-ignore
    // This will be fixed in Astro 6 with Vite 7 support
    // See: https://github.com/withastro/astro/issues/14030
    plugins: [tailwindcss()],
    optimizeDeps: {
      exclude: ["@resvg/resvg-js"],
    },
  },
  image: {
    responsiveStyles: true,
    layout: "constrained",
  },
  env: {
    schema: {
      PUBLIC_GOOGLE_SITE_VERIFICATION: envField.string({
        access: "public",
        context: "client",
        optional: true,
      }),
    },
  },
  experimental: {
    preserveScriptOrder: true,
    fonts: [
      {
        name: "IBM Plex Sans",
        cssVariable: "--font-google-sans-code",
        provider: fontProviders.google(),
        fallbacks: ["system-ui", "sans-serif"],
        weights: [300, 400, 500, 600, 700],
        styles: ["normal", "italic"],
      },
      {
        name: "IBM Plex Mono",
        cssVariable: "--font-fira-code",
        provider: fontProviders.google(),
        fallbacks: ["ui-monospace", "SFMono-Regular", "monospace"],
        weights: [300, 400, 500, 600],
        styles: ["normal", "italic"],
      },
    ],
  },
});
