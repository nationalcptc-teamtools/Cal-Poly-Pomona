#set page(paper: "a4", margin: 2cm)
#set text(font: ("Noto Sans", "Noto Sans Hebrew"), size: 10.5pt)
#set par(justify: true)

= Policy review

The client's information security policy, titled "מדיניות אבטחת מידע", was
last revised in 2024. Its section on remote access ("גישה מרחוק") requires
multi-factor authentication, which we confirmed is enforced for the VPN but
not for the webmail portal.

#text(lang: "he")[
  = סיכום הממצאים

  במהלך הבדיקה נמצאה חולשת SQL injection בשרת ההזמנות, וכן נמצא כי גרסת
  Apache בשרת הראשי חשופה ל-CVE-2026-1234. מומלץ לעדכן את השרת בהקדם
  ולהפעיל אימות דו-שלבי גם בפורטל הדואר.
]

#table(
  columns: (1fr, 1fr),
  table.header([*English*], [*עברית*]),
  [Default credentials], [סיסמאות ברירת מחדל],
  [Missing patches], [עדכונים חסרים],
  [Weak TLS configuration], [הגדרת TLS חלשה],
)

#lorem(60)
