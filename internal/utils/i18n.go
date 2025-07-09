package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// I18n represents internationalization service
type I18n struct {
	defaultLanguage string
	fallbackLang    string
	translations    map[string]map[string]string
	pluralRules     map[string]PluralRule
	locales         map[string]*Locale
	mutex           sync.RWMutex
	loadPath        string
}

// Locale represents locale-specific information
type Locale struct {
	Code         string           `json:"code"`
	Name         string           `json:"name"`
	NativeName   string           `json:"native_name"`
	Direction    string           `json:"direction"` // ltr, rtl
	DateFormat   string           `json:"date_format"`
	TimeFormat   string           `json:"time_format"`
	Currency     CurrencyInfo     `json:"currency"`
	NumberFormat NumberFormatInfo `json:"number_format"`
	Enabled      bool             `json:"enabled"`
}

// CurrencyInfo represents currency information
type CurrencyInfo struct {
	Code   string `json:"code"`
	Symbol string `json:"symbol"`
	Name   string `json:"name"`
}

// NumberFormatInfo represents number formatting information
type NumberFormatInfo struct {
	DecimalSeparator  string `json:"decimal_separator"`
	ThousandSeparator string `json:"thousand_separator"`
	DecimalPlaces     int    `json:"decimal_places"`
}

// PluralRule represents plural rule function
type PluralRule func(n int) string

// TranslationKey represents a translation key with context
type TranslationKey struct {
	Key     string
	Context string
	Default string
}

// TranslationData represents translation data for templates
type TranslationData struct {
	Language     string
	Direction    string
	Translations map[string]string
	Locale       *Locale
}

// SupportedLanguages lists all supported languages
var SupportedLanguages = map[string]string{
	"en": "English",
	"es": "Español",
	"fr": "Français",
	"de": "Deutsch",
	"it": "Italiano",
	"pt": "Português",
	"ru": "Русский",
	"zh": "中文",
	"ja": "日本語",
	"ko": "한국어",
	"ar": "العربية",
	"hi": "हिन्दी",
	"tr": "Türkçe",
	"pl": "Polski",
	"nl": "Nederlands",
}

// Common translation keys
const (
	// General
	KeyYes     = "general.yes"
	KeyNo      = "general.no"
	KeyOK      = "general.ok"
	KeyCancel  = "general.cancel"
	KeySave    = "general.save"
	KeyDelete  = "general.delete"
	KeyEdit    = "general.edit"
	KeyCreate  = "general.create"
	KeyUpdate  = "general.update"
	KeyLoading = "general.loading"
	KeyError   = "general.error"
	KeySuccess = "general.success"

	// Auth
	KeyLogin          = "auth.login"
	KeyRegister       = "auth.register"
	KeyLogout         = "auth.logout"
	KeyForgotPassword = "auth.forgot_password"
	KeyResetPassword  = "auth.reset_password"
	KeyUsername       = "auth.username"
	KeyEmail          = "auth.email"
	KeyPassword       = "auth.password"

	// Posts
	KeyPost       = "posts.post"
	KeyPosts      = "posts.posts"
	KeyCreatePost = "posts.create_post"
	KeyLike       = "posts.like"
	KeyComment    = "posts.comment"
	KeyShare      = "posts.share"
	KeyBookmark   = "posts.bookmark"

	// Users
	KeyProfile   = "users.profile"
	KeyFollowers = "users.followers"
	KeyFollowing = "users.following"
	KeyFollow    = "users.follow"
	KeyUnfollow  = "users.unfollow"
	KeySettings  = "users.settings"

	// Messages
	KeyMessage      = "messages.message"
	KeyMessages     = "messages.messages"
	KeySendMessage  = "messages.send_message"
	KeyConversation = "messages.conversation"

	// Notifications
	KeyNotifications = "notifications.notifications"
	KeyMarkAsRead    = "notifications.mark_as_read"
	KeyMarkAllRead   = "notifications.mark_all_read"

	// Time
	KeyJustNow    = "time.just_now"
	KeyMinuteAgo  = "time.minute_ago"
	KeyMinutesAgo = "time.minutes_ago"
	KeyHourAgo    = "time.hour_ago"
	KeyHoursAgo   = "time.hours_ago"
	KeyDayAgo     = "time.day_ago"
	KeyDaysAgo    = "time.days_ago"
	KeyWeekAgo    = "time.week_ago"
	KeyWeeksAgo   = "time.weeks_ago"
	KeyMonthAgo   = "time.month_ago"
	KeyMonthsAgo  = "time.months_ago"
	KeyYearAgo    = "time.year_ago"
	KeyYearsAgo   = "time.years_ago"

	// Errors
	KeyErrorInvalidCredentials = "errors.invalid_credentials"
	KeyErrorUserNotFound       = "errors.user_not_found"
	KeyErrorPostNotFound       = "errors.post_not_found"
	KeyErrorUnauthorized       = "errors.unauthorized"
	KeyErrorForbidden          = "errors.forbidden"
	KeyErrorInternalServer     = "errors.internal_server"
	KeyErrorValidation         = "errors.validation"
	KeyErrorNetworkError       = "errors.network_error"
)

// NewI18n creates a new internationalization service
func NewI18n(defaultLang, fallbackLang, loadPath string) *I18n {
	return &I18n{
		defaultLanguage: defaultLang,
		fallbackLang:    fallbackLang,
		translations:    make(map[string]map[string]string),
		pluralRules:     make(map[string]PluralRule),
		locales:         make(map[string]*Locale),
		loadPath:        loadPath,
	}
}

// LoadTranslations loads translations from files
func (i18n *I18n) LoadTranslations() error {
	i18n.mutex.Lock()
	defer i18n.mutex.Unlock()

	for langCode := range SupportedLanguages {
		if err := i18n.loadLanguage(langCode); err != nil {
			return fmt.Errorf("failed to load language %s: %w", langCode, err)
		}
	}

	return i18n.loadLocales()
}

// loadLanguage loads translations for a specific language
func (i18n *I18n) loadLanguage(langCode string) error {
	filePath := filepath.Join(i18n.loadPath, langCode+".json")

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	var translations map[string]string
	if err := json.Unmarshal(data, &translations); err != nil {
		return err
	}

	i18n.translations[langCode] = translations
	i18n.pluralRules[langCode] = getPluralRule(langCode)

	return nil
}

// loadLocales loads locale information
func (i18n *I18n) loadLocales() error {
	localesPath := filepath.Join(i18n.loadPath, "locales.json")

	data, err := ioutil.ReadFile(localesPath)
	if err != nil {
		return err
	}

	var locales map[string]*Locale
	if err := json.Unmarshal(data, &locales); err != nil {
		return err
	}

	i18n.locales = locales
	return nil
}

// T translates a key with optional parameters
func (i18n *I18n) T(lang, key string, params ...interface{}) string {
	i18n.mutex.RLock()
	defer i18n.mutex.RUnlock()

	// Get translation
	translation := i18n.getTranslation(lang, key)

	// Apply parameters if provided
	if len(params) > 0 {
		return fmt.Sprintf(translation, params...)
	}

	return translation
}

// TWithContext translates with context
func (i18n *I18n) TWithContext(lang, key, context string, params ...interface{}) string {
	contextKey := fmt.Sprintf("%s.%s", context, key)
	return i18n.T(lang, contextKey, params...)
}

// TPlural translates with plural form
func (i18n *I18n) TPlural(lang, key string, count int, params ...interface{}) string {
	pluralKey := i18n.getPluralKey(lang, key, count)
	return i18n.T(lang, pluralKey, params...)
}

// TChoice translates with choice based on count
func (i18n *I18n) TChoice(lang, key string, count int, params ...interface{}) string {
	return i18n.TPlural(lang, key, count, params...)
}

// getTranslation gets translation for key with fallback
func (i18n *I18n) getTranslation(lang, key string) string {
	// Try requested language
	if translations, exists := i18n.translations[lang]; exists {
		if translation, found := translations[key]; found {
			return translation
		}
	}

	// Try fallback language
	if lang != i18n.fallbackLang {
		if translations, exists := i18n.translations[i18n.fallbackLang]; exists {
			if translation, found := translations[key]; found {
				return translation
			}
		}
	}

	// Try default language
	if lang != i18n.defaultLanguage && i18n.fallbackLang != i18n.defaultLanguage {
		if translations, exists := i18n.translations[i18n.defaultLanguage]; exists {
			if translation, found := translations[key]; found {
				return translation
			}
		}
	}

	// Return key if no translation found
	return key
}

// getPluralKey gets plural key based on count
func (i18n *I18n) getPluralKey(lang, key string, count int) string {
	pluralRule, exists := i18n.pluralRules[lang]
	if !exists {
		pluralRule = i18n.pluralRules[i18n.defaultLanguage]
	}

	if pluralRule != nil {
		pluralForm := pluralRule(count)
		return fmt.Sprintf("%s.%s", key, pluralForm)
	}

	// Default English plural rule
	if count == 1 {
		return key + ".one"
	}
	return key + ".other"
}

// GetLocale returns locale information for language
func (i18n *I18n) GetLocale(lang string) *Locale {
	i18n.mutex.RLock()
	defer i18n.mutex.RUnlock()

	if locale, exists := i18n.locales[lang]; exists {
		return locale
	}

	return i18n.locales[i18n.defaultLanguage]
}

// GetSupportedLanguages returns list of supported languages
func (i18n *I18n) GetSupportedLanguages() map[string]string {
	return SupportedLanguages
}

// IsSupported checks if language is supported
func (i18n *I18n) IsSupported(lang string) bool {
	_, exists := SupportedLanguages[lang]
	return exists
}

// DetectLanguage detects language from Accept-Language header
func (i18n *I18n) DetectLanguage(acceptLanguage string) string {
	if acceptLanguage == "" {
		return i18n.defaultLanguage
	}

	// Parse Accept-Language header
	languages := parseAcceptLanguage(acceptLanguage)

	for _, lang := range languages {
		if i18n.IsSupported(lang) {
			return lang
		}

		// Try language without region (e.g., en from en-US)
		if parts := strings.Split(lang, "-"); len(parts) > 1 {
			if i18n.IsSupported(parts[0]) {
				return parts[0]
			}
		}
	}

	return i18n.defaultLanguage
}

// FormatDate formats date according to locale
func (i18n *I18n) FormatDate(lang string, t time.Time) string {
	locale := i18n.GetLocale(lang)
	if locale.DateFormat != "" {
		return t.Format(locale.DateFormat)
	}
	return t.Format("2006-01-02")
}

// FormatTime formats time according to locale
func (i18n *I18n) FormatTime(lang string, t time.Time) string {
	locale := i18n.GetLocale(lang)
	if locale.TimeFormat != "" {
		return t.Format(locale.TimeFormat)
	}
	return t.Format("15:04")
}

// FormatDateTime formats date and time according to locale
func (i18n *I18n) FormatDateTime(lang string, t time.Time) string {
	locale := i18n.GetLocale(lang)
	dateFormat := locale.DateFormat
	timeFormat := locale.TimeFormat

	if dateFormat == "" {
		dateFormat = "2006-01-02"
	}
	if timeFormat == "" {
		timeFormat = "15:04"
	}

	return t.Format(dateFormat + " " + timeFormat)
}

// FormatRelativeTime formats relative time (e.g., "2 hours ago")
func (i18n *I18n) FormatRelativeTime(lang string, t time.Time) string {
	now := time.Now()
	diff := now.Sub(t)

	switch {
	case diff < time.Minute:
		return i18n.T(lang, KeyJustNow)
	case diff < 2*time.Minute:
		return i18n.T(lang, KeyMinuteAgo)
	case diff < time.Hour:
		minutes := int(diff.Minutes())
		return i18n.T(lang, KeyMinutesAgo, minutes)
	case diff < 2*time.Hour:
		return i18n.T(lang, KeyHourAgo)
	case diff < 24*time.Hour:
		hours := int(diff.Hours())
		return i18n.T(lang, KeyHoursAgo, hours)
	case diff < 48*time.Hour:
		return i18n.T(lang, KeyDayAgo)
	case diff < 7*24*time.Hour:
		days := int(diff.Hours() / 24)
		return i18n.T(lang, KeyDaysAgo, days)
	case diff < 14*24*time.Hour:
		return i18n.T(lang, KeyWeekAgo)
	case diff < 30*24*time.Hour:
		weeks := int(diff.Hours() / (7 * 24))
		return i18n.T(lang, KeyWeeksAgo, weeks)
	case diff < 60*24*time.Hour:
		return i18n.T(lang, KeyMonthAgo)
	case diff < 365*24*time.Hour:
		months := int(diff.Hours() / (30 * 24))
		return i18n.T(lang, KeyMonthsAgo, months)
	case diff < 2*365*24*time.Hour:
		return i18n.T(lang, KeyYearAgo)
	default:
		years := int(diff.Hours() / (365 * 24))
		return i18n.T(lang, KeyYearsAgo, years)
	}
}

// FormatNumber formats number according to locale
func (i18n *I18n) FormatNumber(lang string, number float64) string {
	locale := i18n.GetLocale(lang)

	// Convert to string with appropriate decimal places
	formatted := fmt.Sprintf("%."+fmt.Sprintf("%d", locale.NumberFormat.DecimalPlaces)+"f", number)

	// Replace decimal separator
	if locale.NumberFormat.DecimalSeparator != "." {
		formatted = strings.Replace(formatted, ".", locale.NumberFormat.DecimalSeparator, 1)
	}

	// Add thousand separators
	return addThousandSeparators(formatted, locale.NumberFormat.ThousandSeparator, locale.NumberFormat.DecimalSeparator)
}

// FormatCurrency formats currency according to locale
func (i18n *I18n) FormatCurrency(lang string, amount float64) string {
	locale := i18n.GetLocale(lang)
	formattedNumber := i18n.FormatNumber(lang, amount)
	return locale.Currency.Symbol + formattedNumber
}

// GetTranslationData returns translation data for templates
func (i18n *I18n) GetTranslationData(lang string) *TranslationData {
	locale := i18n.GetLocale(lang)

	return &TranslationData{
		Language:     lang,
		Direction:    locale.Direction,
		Translations: i18n.translations[lang],
		Locale:       locale,
	}
}

// parseAcceptLanguage parses Accept-Language header
func parseAcceptLanguage(acceptLanguage string) []string {
	var languages []string

	parts := strings.Split(acceptLanguage, ",")
	for _, part := range parts {
		lang := strings.TrimSpace(part)
		// Remove quality factor (e.g., en;q=0.9 -> en)
		if idx := strings.Index(lang, ";"); idx > 0 {
			lang = lang[:idx]
		}
		if lang != "" {
			languages = append(languages, lang)
		}
	}

	return languages
}

// addThousandSeparators adds thousand separators to number string
func addThousandSeparators(number, thousandSep, decimalSep string) string {
	parts := strings.Split(number, decimalSep)
	integerPart := parts[0]

	// Add thousand separators to integer part
	if len(integerPart) > 3 {
		var result []rune
		for i, char := range integerPart {
			if i > 0 && (len(integerPart)-i)%3 == 0 {
				result = append(result, []rune(thousandSep)...)
			}
			result = append(result, char)
		}
		integerPart = string(result)
	}

	// Reconstruct number
	if len(parts) > 1 {
		return integerPart + decimalSep + parts[1]
	}
	return integerPart
}

// getPluralRule returns plural rule function for language
func getPluralRule(lang string) PluralRule {
	switch lang {
	case "en", "de", "nl", "it", "es", "pt":
		return func(n int) string {
			if n == 1 {
				return "one"
			}
			return "other"
		}
	case "fr":
		return func(n int) string {
			if n == 0 || n == 1 {
				return "one"
			}
			return "other"
		}
	case "ru", "pl":
		return func(n int) string {
			if n%10 == 1 && n%100 != 11 {
				return "one"
			}
			if n%10 >= 2 && n%10 <= 4 && (n%100 < 10 || n%100 >= 20) {
				return "few"
			}
			return "many"
		}
	case "ar":
		return func(n int) string {
			if n == 0 {
				return "zero"
			}
			if n == 1 {
				return "one"
			}
			if n == 2 {
				return "two"
			}
			if n%100 >= 3 && n%100 <= 10 {
				return "few"
			}
			if n%100 >= 11 && n%100 <= 99 {
				return "many"
			}
			return "other"
		}
	default:
		// Default English rule
		return func(n int) string {
			if n == 1 {
				return "one"
			}
			return "other"
		}
	}
}

// GetLanguageDirection returns text direction for language
func GetLanguageDirection(lang string) string {
	rtlLanguages := map[string]bool{
		"ar": true, // Arabic
		"he": true, // Hebrew
		"fa": true, // Persian
		"ur": true, // Urdu
	}

	if rtlLanguages[lang] {
		return "rtl"
	}
	return "ltr"
}

// NormalizeLanguageCode normalizes language code
func NormalizeLanguageCode(lang string) string {
	if lang == "" {
		return "en"
	}

	// Convert to lowercase
	lang = strings.ToLower(lang)

	// Extract language code without region
	if parts := strings.Split(lang, "-"); len(parts) > 0 {
		return parts[0]
	}

	return lang
}
