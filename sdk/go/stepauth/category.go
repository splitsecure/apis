package stepauth

// Category is a value from the closed v1 action-category registry; anything
// outside it is rejected as unknown_category.
type Category = string

const (
	CategoryDataRead          Category = "data.read"
	CategoryDataExport        Category = "data.export"
	CategoryDataModify        Category = "data.modify"
	CategoryDataDelete        Category = "data.delete"
	CategoryIdentityCreate    Category = "identity.create"
	CategoryIdentityModify    Category = "identity.modify"
	CategoryIdentityEscalate  Category = "identity.escalate"
	CategoryIdentityDisable   Category = "identity.disable"
	CategoryInfraModify       Category = "infra.modify"
	CategoryInfraDestroy      Category = "infra.destroy"
	CategoryFinancialTransfer Category = "financial.transfer"
	CategoryFinancialApprove  Category = "financial.approve"
	CategoryCodeDeploy        Category = "code.deploy"
	CategoryCodeRelease       Category = "code.release"
	CategoryCommunicationSend Category = "communication.send"
	CategoryAccessGrant       Category = "access.grant"
	CategoryAccessRevoke      Category = "access.revoke"
)

var categoryRegistry = map[Category]struct{}{
	CategoryDataRead: {}, CategoryDataExport: {}, CategoryDataModify: {}, CategoryDataDelete: {},
	CategoryIdentityCreate: {}, CategoryIdentityModify: {}, CategoryIdentityEscalate: {}, CategoryIdentityDisable: {},
	CategoryInfraModify: {}, CategoryInfraDestroy: {},
	CategoryFinancialTransfer: {}, CategoryFinancialApprove: {},
	CategoryCodeDeploy: {}, CategoryCodeRelease: {},
	CategoryCommunicationSend: {},
	CategoryAccessGrant:       {}, CategoryAccessRevoke: {},
}

// IsValidCategory reports whether c is in the closed v1 registry.
func IsValidCategory(c Category) bool {
	_, ok := categoryRegistry[c]
	return ok
}
