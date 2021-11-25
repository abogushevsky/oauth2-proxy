package authorization

import "regexp"

/*
	Rules index allows to reduce the amount of path regexes to test. Every request contains username,
	a slice of roles, method and path. Configuration gives us a number of [ruleInfo] instances which can be
	grouped by username, then by role and by method. This way we can reduce the amount of regexes to check
	for each request.

	TODO: Grouping by path regex first might be more efficient because the amount of resources provided by the
	TODO: service might be significantly less than amount of users. This way we might check more regexes per request
	TODO: but we consume less memory
*/
type rulesIndex map[string]map[string]map[string][]regexp.Regexp

type ruleInfo struct {
	user      string
	group     string
	method    string
	pathRegex regexp.Regexp
}

type AuthManager interface {
	IsAuthorized(user string, roles []string, path string, method string) bool
}

type ConfigBasedAuthManager struct {
	index rulesIndex
}

func NewConfigBasedAuthManager(rules []ruleInfo) *ConfigBasedAuthManager {
	index := rulesIndex{}

	for _, rule := range rules {
		byGroup, userExists := index[rule.user]
		if !userExists {
			byGroup = map[string]map[string][]regexp.Regexp{}
			byGroup[rule.group] = map[string][]regexp.Regexp{}
		}
		byMethod, groupExists := byGroup[rule.group]
		if !groupExists {
			byMethod = map[string][]regexp.Regexp{}
			byMethod[rule.method] = []regexp.Regexp{}
		}

		regexes, methodExists := byMethod[rule.method]
		if !methodExists {
			regexes = []regexp.Regexp{}
		}

		regexes = append(regexes, rule.pathRegex)
	}

	return &ConfigBasedAuthManager{index: index}
}

func (c ConfigBasedAuthManager) IsAuthorized(user string, roles []string, path string, method string) bool {
	rolesIndex, exists := c.index[user]
	if !exists {
		return true
	}

	for _, role := range roles {
		methodsIndex, exists := rolesIndex[role]
		if exists {
			regexes, exists := methodsIndex[method]
			if exists {
				for _, regex := range regexes {
					if regex.MatchString(path) {
						return true
					}
				}
			}
		}
	}

	return false
}
