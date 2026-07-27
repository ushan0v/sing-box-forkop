package clashapi

var (
	CtxKeyProxyName    = contextKey("proxy name")
	CtxKeyProviderName = contextKey("provider name")
	CtxKeyProxy        = contextKey("proxy")
	CtxKeyProvider     = contextKey("provider")
	CtxKeyRuleProvider = contextKey("rule provider")
)

type contextKey string

func (c contextKey) String() string {
	return "clash context key " + string(c)
}
