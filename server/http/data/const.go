package data

type Market string

const (
	MarketGlobal        Market = "GLOBAL"
	MarketSingapore     Market = "SG"
	MarketHongKong      Market = "HK"
	MarketUnitedStates  Market = "US"
	MarketEEA           Market = "EEA"
	MarketUnitedKingdom Market = "UK"
	MarketUAE           Market = "UAE"
	MarketAustralia     Market = "AU"
	MarketJapan         Market = "JP"
	MarketSouthKorea    Market = "KR"
	MarketTurkey        Market = "TR"
	MarketBrazil        Market = "BR"
	MarketLatinAmerica  Market = "LATAM"
	MarketSoutheastAsia Market = "SEA"
)

var validMarkets = map[Market]struct{}{
	MarketGlobal: {}, MarketSingapore: {}, MarketHongKong: {}, MarketUnitedStates: {},
	MarketEEA: {}, MarketUnitedKingdom: {}, MarketUAE: {}, MarketAustralia: {},
	MarketJapan: {}, MarketSouthKorea: {}, MarketTurkey: {}, MarketBrazil: {},
	MarketLatinAmerica: {}, MarketSoutheastAsia: {},
}

func IsValidMarket(v string) bool {
	_, ok := validMarkets[Market(v)]
	return ok
}

type Language string

const (
	LanguageEnglish            Language = "en"
	LanguageSimplifiedChinese  Language = "zh-CN"
	LanguageTraditionalChinese Language = "zh-TW"
	LanguageSpanish            Language = "es"
	LanguagePortugueseBrazil   Language = "pt-BR"
	LanguageJapanese           Language = "ja"
	LanguageKorean             Language = "ko"
	LanguageArabic             Language = "ar"
	LanguageTurkish            Language = "tr"
	LanguageFrench             Language = "fr"
	LanguageGerman             Language = "de"
	LanguageVietnamese         Language = "vi"
	LanguageIndonesian         Language = "id"
	LanguageThai               Language = "th"
)

var validLanguages = map[Language]struct{}{
	LanguageEnglish: {}, LanguageSimplifiedChinese: {}, LanguageTraditionalChinese: {},
	LanguageSpanish: {}, LanguagePortugueseBrazil: {}, LanguageJapanese: {}, LanguageKorean: {},
	LanguageArabic: {}, LanguageTurkish: {}, LanguageFrench: {}, LanguageGerman: {},
	LanguageVietnamese: {}, LanguageIndonesian: {}, LanguageThai: {},
}

func IsValidLanguage(v string) bool {
	_, ok := validLanguages[Language(v)]
	return ok
}
