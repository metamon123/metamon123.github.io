export const SITE = {
  website: "https://metamon123.github.io/",
  author: "metamon123",
  profile: "https://github.com/metamon123",
  desc: "IT & Security & Fun by metamon123",
  title: "📡 10.825 GHz 의 🔒💻",
  ogImage: "og.png",
  lightAndDarkMode: false,
  postPerIndex: 4,
  postPerPage: 6,
  scheduledPostMargin: 15 * 60 * 1000, // 15 minutes
  showArchives: true,
  showBackButton: true, // show back button in post detail
  editPost: {
    enabled: false,
    text: "Edit page",
    url: "https://github.com/metamon123/metamon123.github.io/edit/master/",
  },
  dynamicOgImage: true,
  defaultPostLanguage: "mixed", // "mixed" | "ko" | "en"
  dir: "ltr", // "rtl" | "auto"
  lang: "ko", // html lang code. Set this empty and default will be "en"
  timezone: "Asia/Seoul", // Default global timezone (IANA format) https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
} as const;
