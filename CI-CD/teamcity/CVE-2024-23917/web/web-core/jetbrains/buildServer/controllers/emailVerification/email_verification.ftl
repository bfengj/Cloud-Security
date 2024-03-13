<#-- @ftlvariable name="verifyUrl" type="java.lang.String" -->
<#-- @ftlvariable name="user" type="jetbrains.buildServer.users.SUser" -->
<#global subject>Verify your email address for TeamCity</#global>

<#global body>
  Hi ${user.descriptiveName},

  Email address verification procedure for user '${user.username}' has been started on ${serverUrl}.
  Confirm email ${emailAddress} and complete the verification procedure using the link ${verifyUrl}
</#global>

<#global bodyHtml>
  <div style="padding: 5px 5px; font-size: 14px; line-height: 20px">
      <p>Hi ${user.descriptiveName?html},</p>

      <p>
          Email address verification procedure for user '${user.username?html}' has been started on <a href="${serverUrl}">${serverUrl}</a>.<br/>
          Click the link below to confirm email ${emailAddress?html} and complete the verification procedure:
      </p>
      <p><a href="${verifyUrl}">Confirm Email Address</a></p>

  </div>
</#global>
