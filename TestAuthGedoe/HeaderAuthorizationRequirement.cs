using Microsoft.AspNetCore.Authorization;

namespace TestAuthGedoe;

public class HeaderAuthorizationRequirement : AuthorizationHandler<HeaderAuthorizationRequirement>, IAuthorizationRequirement
{
   public HeaderAuthorizationRequirement(string headerKey)
   {
      ArgumentException.ThrowIfNullOrEmpty(headerKey);

      this.HeaderKey = headerKey;
   }

   /// <summary>
   /// Gets the name of the header key that should be present.
   /// </summary>
   public string HeaderKey { get; }

   protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, HeaderAuthorizationRequirement requirement)
   {
      if (context.Resource is HttpContext httpContext)
      {
         var headerValue = httpContext.Request.Headers.SingleOrDefault(x => string.Equals(x.Key, Constants.ApiHeaderKey, StringComparison.OrdinalIgnoreCase)).Value.FirstOrDefault();
         if (string.IsNullOrWhiteSpace(headerValue))
         {
            context.Fail();
         }
         else
         {
            context.Succeed(requirement);
         }
         return Task.CompletedTask;
      }

      context.Fail();
      return Task.CompletedTask;
   }
}

public static class AuthorizationPolicyBuilderExtensionMethods
{
   public static AuthorizationPolicyBuilder RequireHeader(this AuthorizationPolicyBuilder builder, string header)
   {
      builder?.Requirements.Add(new HeaderAuthorizationRequirement(header));

      return builder;
   }
}
