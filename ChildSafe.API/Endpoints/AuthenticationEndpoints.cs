using ChildSafe.API.Dtos;
using ChildSafe.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ChildSafe.API.Endpoints
{
    public static class AuthenticationEndpoints
    {
        private const string endpointGroup = "Authentication";
        public static void MapAuthenticationEndpoints(this IEndpointRouteBuilder app)
        {

            app.MapGet("/users/{userId}/roles", async (string userId, UserManager<AppUser> userManager) =>
            {
                var user = await userManager.FindByIdAsync(userId);
                if (user == null)
                    return Results.NotFound("User not found.");

                var roles = await userManager.GetRolesAsync(user);
                return Results.Ok(roles);
            })
            .WithTags(endpointGroup)
            .RequireAuthorization();

            app.MapPost("/users/{userId}/assign-role", async (string userId, string roleName, UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager) =>
            {
                var user = await userManager.FindByIdAsync(userId);
                if (user == null)
                    return Results.NotFound("User not found.");

                if (!await roleManager.RoleExistsAsync(roleName))
                    return Results.BadRequest("Role does not exist.");

                var result = await userManager.AddToRoleAsync(user, roleName);

                return result.Succeeded ? Results.Ok($"User added to role '{roleName}'") :
                                          Results.BadRequest(result.Errors);
            }).WithTags(endpointGroup)
              .RequireAuthorization("AdminOnly");

            app.MapPost("/users/{userId}/remove-role", async (string userId, string roleName, UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager) =>
            {
                var user = await userManager.FindByIdAsync(userId);
                if (user == null)
                    return Results.NotFound("User not found.");

                if (!await roleManager.RoleExistsAsync(roleName))
                    return Results.BadRequest("Role does not exist.");

                var result = await userManager.RemoveFromRoleAsync(user, roleName);

                return result.Succeeded
                    ? Results.Ok($"Role '{roleName}' removed from user.")
                    : Results.BadRequest(result.Errors);
            }).WithTags(endpointGroup)
            .RequireAuthorization();


            app.MapPost("/newrole", async (string roleName, RoleManager<IdentityRole> roleManager) =>
            {
                if (await roleManager.RoleExistsAsync(roleName))
                    return Results.BadRequest("Role already exists.");

                var result = await roleManager.CreateAsync(new IdentityRole(roleName));

                return result.Succeeded ? Results.Ok($"Role '{roleName}' created.") :
                                          Results.BadRequest(result.Errors);
            }).WithTags(endpointGroup)
            .RequireAuthorization("AdminOnly");

            app.MapGet("/my-userid", (HttpContext context) =>
            {
                var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                return Results.Ok(new { UserId = userId });
            }).RequireAuthorization("AdminOnly")
            .WithTags(endpointGroup);

            app.MapGet("/auth-users", (UserManager<AppUser> userManager) =>
            {
                var users = userManager.Users.Select(u => new
                {
                    u.Id,
                    u.UserName,
                    u.Email
                });

                return Results.Ok(users);
            }).RequireAuthorization("AdminOnly")
            .WithTags(endpointGroup);

            app.MapGet("/users/by-email/{email}", async (string email, UserManager<AppUser> userManager) =>
            {
                var user = await userManager.FindByEmailAsync(email);
                return user != null
                    ? Results.Ok(user)
                    : Results.NotFound("User not found.");
            })
                .RequireAuthorization("AdminOnly")
                .WithTags(endpointGroup);


            app.MapPost("/signup", async ([FromServices] UserManager<AppUser> userManager, [FromBody] SignupRequest request) =>
            {
                if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
                    return Results.BadRequest(new { message = "Email and Password are required" });

                var user = new AppUser
                {
                    Name = request.FullName,
                    UserName = request.Email,
                    Email = request.Email,
                    PhoneNumber = request.Phone,                   
                };

                var result = await userManager.CreateAsync(user, request.Password);

                if (result.Succeeded)
                    return Results.Ok(new { message = "User registered successfully" });

                return Results.BadRequest(result.Errors);
            }).WithTags(endpointGroup);

            app.MapPost("/login", async (UserManager<AppUser> userManager, IConfiguration config, LoginRequest login, HttpResponse response) =>
            {
                var user = await userManager.FindByNameAsync(login.Email);
                if (user == null || !await userManager.CheckPasswordAsync(user, login.Password))
                    return Results.Unauthorized();

                var userRoles = await userManager.GetRolesAsync(user);
                var claims = new List<Claim> { new Claim(ClaimTypes.NameIdentifier, user.Id), new Claim(ClaimTypes.Name, user.UserName) };
                claims.AddRange(userRoles.Select(r => new Claim(ClaimTypes.Role, r)));

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));
                var token = new JwtSecurityToken(
                    issuer: config["Jwt:Issuer"],
                    audience: config["Jwt:Audience"],
                    claims: claims,
                    expires: DateTime.UtcNow.AddHours(1),
                    signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
                );

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

                return Results.Ok(tokenString);
            }).WithTags(endpointGroup);

            app.MapPost("/logout", (HttpResponse response) =>
            {
                response.Cookies.Delete("token");
                return Results.Ok(new { message = "Logged out" });
            }).WithTags(endpointGroup);

            app.MapGet("/my-roles", (HttpContext context) =>
            {
                var roles = context.User.Claims
                    .Where(c => c.Type == ClaimTypes.Role)
                    .Select(c => c.Value)
                    .ToList();

                return Results.Ok(new { Roles = roles });
            }).RequireAuthorization().WithTags(endpointGroup);
        }

    }

}
