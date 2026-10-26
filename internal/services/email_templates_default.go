package services

import "shieldgate/internal/models"

// defaultEmailTemplates are used when a tenant has not defined its own
// template of the same name, so account emails work out of the box.
// Placeholders are {{name}}; values are HTML-escaped in BodyHTML.
var defaultEmailTemplates = map[string]models.EmailTemplate{
	string(models.EmailTemplateEmailVerification): {
		Name:     string(models.EmailTemplateEmailVerification),
		Subject:  "Verify your email address",
		IsActive: true,
		BodyText: "Hi {{user_name}},\n\n" +
			"Confirm your email address by opening this link:\n\n{{verification_link}}\n\n" +
			"The link expires in {{expires_hours}} hours. If you did not create an account, ignore this email.\n",
		BodyHTML: `<p>Hi {{user_name}},</p>` +
			`<p>Confirm your email address by opening this link:</p>` +
			`<p><a href="{{verification_link}}">Verify email address</a></p>` +
			`<p>The link expires in {{expires_hours}} hours. If you did not create an account, ignore this email.</p>`,
		Variables: models.StringArray{"user_name", "verification_link", "expires_hours"},
	},
	string(models.EmailTemplatePasswordReset): {
		Name:     string(models.EmailTemplatePasswordReset),
		Subject:  "Reset your password",
		IsActive: true,
		BodyText: "Hi {{user_name}},\n\n" +
			"Someone asked to reset the password for your account. To choose a new password, open this link:\n\n{{reset_link}}\n\n" +
			"The link expires in {{expires_minutes}} minutes and works once. If you did not ask for this, ignore this email; your password is unchanged.\n",
		BodyHTML: `<p>Hi {{user_name}},</p>` +
			`<p>Someone asked to reset the password for your account. To choose a new password, open this link:</p>` +
			`<p><a href="{{reset_link}}">Reset password</a></p>` +
			`<p>The link expires in {{expires_minutes}} minutes and works once. If you did not ask for this, ignore this email; your password is unchanged.</p>`,
		Variables: models.StringArray{"user_name", "reset_link", "expires_minutes"},
	},
	string(models.EmailTemplatePasswordChanged): {
		Name:     string(models.EmailTemplatePasswordChanged),
		Subject:  "Your password was changed",
		IsActive: true,
		BodyText: "Hi {{user_name}},\n\n" +
			"The password for your account was just changed. " +
			"If this was not you, reset your password immediately and contact your administrator.\n",
		BodyHTML: `<p>Hi {{user_name}},</p>` +
			`<p>The password for your account was just changed.</p>` +
			`<p>If this was not you, reset your password immediately and contact your administrator.</p>`,
		Variables: models.StringArray{"user_name"},
	},
}
