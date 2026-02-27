# Custom Markdown Features

This document lists the custom Markdown features available in this project and
how to use them.

## Callouts (admonitions)

Supported types: `note`, `tip`, `info`, `warning`.

Syntax:

````md
:::note[Title]
Content...
:::

:::warning[주의]
Content...
:::
````

Notes:
- The title in `[...]` is required for a custom label.
- If you omit a title, the type name is used.

## Collapsible blocks

Use HTML details/summary.

````md
<details>
<summary>Title</summary>

Content...
</details>
````

## Code block captions

Bottom caption (default):

````md
```python caption="injected payload"
print("hello")
```
````

Top caption:

````md
```python captionTop="payload generator"
print("hello")
```
````

## Code block file labels

Use the `file="..."` meta to show a small label.

````md
```python file="solve.py"
print("hello")
```
````

Notes:
- Spaces are not supported in `file="..."`. Use underscores or hyphens.

## Code block wrapping (per block)

Use `wrap` to enable soft wrapping and disable horizontal scrolling.

````md
```python wrap
print("very long line ...")
```
````

## Highlight / add / delete lines (Shiki notation)

Highlight a line:

````md
```ts
console.log("normal")
console.log("highlight") // [!code highlight]
```
````

Highlight a range (note: count starts on next line in matchAlgorithm v3):

````md
```ts
// [!code highlight:2]
console.log("highlighted")
console.log("highlighted")
console.log("normal")
```
````

Added/removed lines:

````md
```ts
console.log("old") // [!code --]
console.log("new") // [!code ++]
```
````

Word highlight:

````md
```ts
// [!code word:token]
const token = "secret"
```
````

## Blockquote styling

Blockquotes do not show decorative quotation marks.

````md
> This is a quote without extra quotation marks.
````
