package rule

type RuleIdentity struct {
	RulesetID string `json:"ruleset_id"`
	RuleID    string `json:"rule_id"`
}

func (id RuleIdentity) IsZero() bool {
	return id.RulesetID == "" && id.RuleID == ""
}

type CanonicalRuleID string

func (id RuleIdentity) CanonicalRuleID() CanonicalRuleID {
	return CanonicalRuleID(id.RulesetID + "/" + id.RuleID)
}

func (id CanonicalRuleID) String() string {
	return string(id)
}
