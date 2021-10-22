package accesscontrol

import (
	"context"
	"fmt"
	"strings"

	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/services/sqlstore"
)

// Scope builds scope from parts
// e.g. Scope("users", "*") return "users:*"
func Scope(parts ...string) string {
	b := strings.Builder{}
	for i, c := range parts {
		if i != 0 {
			b.WriteRune(':')
		}
		b.WriteString(c)
	}
	return b.String()
}

// Parameter returns injectable scope part, based on URL parameters.
// e.g. Scope("users", Parameter(":id")) or "users:" + Parameter(":id")
func Parameter(key string) string {
	return fmt.Sprintf(`{{ index .URLParams "%s" }}`, key)
}

// Field returns an injectable scope part for selected fields from the request's context available in accesscontrol.ScopeParams.
// e.g. Scope("orgs", Parameter("OrgID")) or "orgs:" + Parameter("OrgID")
func Field(key string) string {
	return fmt.Sprintf(`{{ .%s }}`, key)
}

type KeywordScopeResolveFunc func(*models.SignedInUser) (string, error)

// ScopeResolver contains a map of functions to resolve scope keywords such as `self` or `current` into `id` based scopes
type ScopeResolver struct {
	keywordResolvers   map[string]KeywordScopeResolveFunc
	attributeResolvers map[string]AttributeScopeResolveFunc
}

func NewScopeResolver() ScopeResolver {
	return ScopeResolver{
		keywordResolvers: map[string]KeywordScopeResolveFunc{
			"orgs:current": resolveCurrentOrg,
			"users:self":   resolveUserSelf,
		},
		attributeResolvers: map[string]AttributeScopeResolveFunc{},
	}
}

func (s *ScopeResolver) AddKeywordResolver(keyword string, fn KeywordScopeResolveFunc) {
	s.keywordResolvers[keyword] = fn
}

func (s *ScopeResolver) AddAttributeResolver(prefix string, fn AttributeScopeResolveFunc) {
	s.attributeResolvers[prefix] = fn
}

func resolveCurrentOrg(u *models.SignedInUser) (string, error) {
	return Scope("orgs", "id", fmt.Sprintf("%v", u.OrgId)), nil
}

func resolveUserSelf(u *models.SignedInUser) (string, error) {
	return Scope("users", "id", fmt.Sprintf("%v", u.UserId)), nil
}

// ResolveKeyword resolves scope with keywords such as `self` or `current` into `id` based scopes
func (s *ScopeResolver) ResolveKeyword(user *models.SignedInUser, permission Permission) (*Permission, error) {
	if fn, ok := s.keywordResolvers[permission.Scope]; ok {
		resolvedScope, err := fn(user)
		if err != nil {
			return nil, fmt.Errorf("could not resolve \"%v\": %v", permission.Scope, err)
		}
		permission.Scope = resolvedScope
	}
	return &permission, nil
}

type AttributeScopeResolveFunc func(ctx context.Context, user *models.SignedInUser, initialScope string) (string, error)

// TODO discuss if that pattern is fine. It will become useful when registering Scope Resolvers that rely on different `Store`.
func NewResolveDatasourceNameFunc(db *sqlstore.SQLStore) AttributeScopeResolveFunc {
	return func(ctx context.Context, user *models.SignedInUser, initialScope string) (string, error) {
		dsName := strings.Split(initialScope, ":")[2]

		query := models.GetDataSourceQuery{Name: dsName, OrgId: user.OrgId}
		if err := db.GetDataSource(ctx, &query); err != nil {
			return "", err
		}

		return Scope("datasources", "id", fmt.Sprintf("%v", query.Result.Id)), nil
	}
}

// GetResolveAttributeScopeModifier resolves scopes with attributes such as `name` or `uid` into `id` based scopes
func (s *ScopeResolver) GetResolveAttributeScopeModifier(ctx context.Context, user *models.SignedInUser) ScopeModifier {
	return func(scope string) (string, error) {
		// TODO implement caching to speed this up
		var err error
		resolvedScope := scope
		prefix := scopePrefix(scope)
		if fn, ok := s.attributeResolvers[prefix]; ok {
			resolvedScope, err = fn(ctx, user, scope)
			if err != nil {
				return "", fmt.Errorf("could not resolve %v: %v", scope, err)
			}
		}
		return resolvedScope, nil
	}
}

func scopePrefix(scope string) string {
	parts := strings.Split(scope, ":")
	n := len(parts) - 1
	parts[n] = ""
	return strings.Join(parts, ":")
}
