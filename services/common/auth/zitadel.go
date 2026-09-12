package auth

// ZitadelMapper extracts UserContext from Zitadel tokens. The roles claim
// `urn:zitadel:iam:org:project:roles` has the shape
// map[role]map[orgID]orgName; we require exactly ONE unambiguous org.
type ZitadelMapper struct{}

func (ZitadelMapper) Map(claims map[string]any) (UserContext, error) {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return UserContext{}, errInvalidToken
	}
	rolesRaw, _ := claims["urn:zitadel:iam:org:project:roles"].(map[string]any)

	orgID := ""
	roles := make([]string, 0, len(rolesRaw))
	for role, orgsAny := range rolesRaw {
		orgs, ok := orgsAny.(map[string]any)
		if !ok {
			return UserContext{}, errInvalidToken
		}
		for org := range orgs {
			if org == "" {
				return UserContext{}, errInvalidToken
			}
			if orgID != "" && orgID != org {
				return UserContext{}, errInvalidToken // never flatten roles across orgs
			}
			orgID = org
		}
		roles = append(roles, role)
	}
	return UserContext{Subject: sub, OrgID: orgID, Roles: roles}, nil
}
