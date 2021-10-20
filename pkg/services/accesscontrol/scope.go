package accesscontrol

import (
	"context"
	"fmt"
	"strings"

	"github.com/grafana/grafana/pkg/models"
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
		attributeResolvers: map[string]AttributeScopeResolveFunc{
			"datasources:name:": resolveDatasourceName,
		},
	}
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

type AttributeScopeResolveFunc func(ctx context.Context, user *models.SignedInUser, db ScopeResolverStore, initialScope string) (string, error)

func resolveDatasourceName(ctx context.Context, user *models.SignedInUser, db ScopeResolverStore, initialScope string) (string, error) {
	dsName := strings.Split(initialScope, ":")[2]

	query := models.GetDataSourceQuery{Name: dsName, OrgId: user.OrgId}
	if err := db.GetDataSource(ctx, &query); err != nil {
		return "", err
	}

	return Scope("datasources", "id", fmt.Sprintf("%v", query.Result.Id)), nil
}

// TODO maybe think of another design since this prevents registering resolutions
// ScopeResolverStore holds the methods required for AttributeScopeResolution
type ScopeResolverStore interface {
	GetDataSource(context.Context, *models.GetDataSourceQuery) error
}

// ResolveAttribute resolves scopes with attributes such as `name` or `uid` into `id` based scopes
func (s *ScopeResolver) ResolveAttribute(ctx context.Context, user *models.SignedInUser, db ScopeResolverStore, evaluator Evaluator) (Evaluator, error) {
	if evaluator == nil {
		return nil, nil
	}

	// TODO simplify, this way of doing seems a bit complex
	rebaseScope := func(scope string) (string, error) {
		var err error
		resolvedScope := scope
		prefix := scopePrefix(scope)
		if fn, ok := s.attributeResolvers[prefix]; ok {
			resolvedScope, err = fn(ctx, user, db, scope)
			if err != nil {
				return "", fmt.Errorf("could not resolve %v: %v", scope, err)
			}
		}
		return resolvedScope, nil
	}

	return evaluator.ResolveScopes(rebaseScope)
}

func scopePrefix(scope string) string {
	parts := strings.Split(scope, ":")
	n := len(parts) - 1
	parts[n] = ""
	return strings.Join(parts, ":")
}
