import { slugifyStr } from "./slugify";
import type { CollectionEntry } from "astro:content";

const getUniqueCategories = (posts: CollectionEntry<"blog">[]) =>
  posts
    .flatMap(post => post.data.categories)
    .map(category => category.trim())
    .filter(Boolean)
    .filter(
      (value, index, self) => self.findIndex(item => item === value) === index
    )
    .sort((a, b) => a.localeCompare(b))
    .map(category => ({
      category: slugifyStr(category),
      categoryName: category,
    }));

export default getUniqueCategories;
