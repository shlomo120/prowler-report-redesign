# Prowler Report Redesign

**[Live demo](https://shlomo120.github.io/prowler-report-redesign/prowler_report_redesign.html)** · [English](#english) | [עברית](#עברית)

## English

An offline redesign of [Prowler](https://github.com/prowler-cloud/prowler) HTML reports: an executive dashboard, dark/light mode, search, filters, sorting, paging, expandable details and CSV export, all in one standalone HTML file.

**View the demo report online:** https://shlomo120.github.io/prowler-report-redesign/prowler_report_redesign.html

### Files

| File | Description |
|------|-------------|
| `prowler_report_redesign.py` | Converts a Prowler HTML report (`prowler-output-*.html`) into the redesigned report |
| `prowler_report_redesign.html` | Demo report with **100 mock findings** (project `acme-demo`), no real scan data |

### Usage

Requires Python 3.7+ and only the standard library. No internet access is needed.

```bash
python prowler_report_redesign.py prowler-output-myproject-20260101000000.html
python prowler_report_redesign.py report.html -o Redesigned_Report.html
python prowler_report_redesign.py reports/*.html -o reports/redesigned
```

Open the output HTML file in any browser.

---

<div dir="rtl">

## עברית

עיצוב מחדש של דוחות ה-HTML של [Prowler](https://github.com/prowler-cloud/prowler), שעובד גם ללא חיבור לאינטרנט. הדוח כולל דשבורד מנהלים, מצב כהה/בהיר, חיפוש, מסננים, מיון, דפדוף, פירוט מורחב לכל ממצא וייצוא ל-CSV, והכול בקובץ HTML עצמאי אחד.

**צפייה בדוח לדוגמה אונליין:** https://shlomo120.github.io/prowler-report-redesign/prowler_report_redesign.html

### קבצים

| קובץ | תיאור |
|------|-------|
| `prowler_report_redesign.py` | ממיר דוח HTML של Prowler (`prowler-output-*.html`) לדוח בעיצוב החדש |
| `prowler_report_redesign.html` | דוח לדוגמה עם **100 ממצאים מדומים** (פרויקט `acme-demo`), ללא נתוני סריקה אמיתיים |

### שימוש

נדרש Python בגרסה 3.7 ומעלה, עם הספרייה הסטנדרטית בלבד. אין צורך בחיבור לאינטרנט.

</div>

```bash
python prowler_report_redesign.py prowler-output-myproject-20260101000000.html
python prowler_report_redesign.py report.html -o Redesigned_Report.html
python prowler_report_redesign.py reports/*.html -o reports/redesigned
```

<div dir="rtl">

פתחו את קובץ ה-HTML שנוצר בכל דפדפן.

</div>
