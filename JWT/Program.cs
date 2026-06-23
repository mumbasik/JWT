using Microsoft.AspNetCore.DataProtection;
using System.Text.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.EntityFrameworkCore;

namespace Errors
{
    public class Program
    {
       
        public class User
        {
            public int Id { get; set; }
            public string Email { get; set; }
            public string PasswordHash { get; set; } 
            public string? Name { get; set; }
        }

        public class MovieShow
        {
            public int Id { get; set; }
            public string Title { get; set; } 
            public DateTime StartTime { get; set; }
            public int Duration { get; set; }
            public int AvailableSeats { get; set; }
        }

        public class Booking
        {
            public int Id { get; set; }
            public int UserId { get; set; }
            public int MovieShowId { get; set; }
            public int NumberOfSeats { get; set; }
            public DateTime BookingTime { get; set; }
        }

       
        public class AppDbContext : DbContext
        {
            public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
            public DbSet<User> Users => Set<User>();
            public DbSet<MovieShow> MovieShows => Set<MovieShow>();
            public DbSet<Booking> Bookings => Set<Booking>();
        }

        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            
            builder.Services.AddDbContext<AppDbContext>(options => options.UseInMemoryDatabase("TicketBookingDb"));

            const string JWTSecret = "SuperLongAndSecureSecret";
            const string JWTIssuer = "TicketCinemaIssuer";
            const string JWTAudience = "TicketCinemaAudience";


            builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.Cookie.Name = "CinemaCookie";
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
    })
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = JWTIssuer,
            ValidAudience = JWTAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JWTSecret))
        };
    })
    
    .AddOAuth("GitHub", options =>
    {
        options.ClientId = "Ov23litvC6UuuTeEozMZ";
        options.ClientSecret = "74b0fde597c02be5db3322f5f1ad76990fa16485";
        options.ClaimsIssuer = "GitHub";

        
        options.CallbackPath = new PathString("/signin-github");

        
        options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
        options.TokenEndpoint = "https://github.com/login/oauth/access_token";
        options.UserInformationEndpoint = "https://api.github.com/user";

       
        options.Scope.Add("user:email");

      
        options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
        options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
        options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");

       
        options.Events = new Microsoft.AspNetCore.Authentication.OAuth.OAuthEvents
        {
            OnCreatingTicket = async context =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                request.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", context.AccessToken);

                var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
                response.EnsureSuccessStatusCode();

                using var user = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                context.RunClaimActions(user.RootElement);
            }
        };
    });




            builder.Services.AddAuthorization();

            var app = builder.Build();

            using (var scope = app.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                if (!db.MovieShows.Any())
                {
                    db.MovieShows.AddRange(
                        new MovieShow { Title = "Interstellar", StartTime = DateTime.Now.AddHours(1), Duration = 169, AvailableSeats = 100 },
                        new MovieShow { Title = "Inception", StartTime = DateTime.Now.AddHours(3), Duration = 148, AvailableSeats = 100 },
                        new MovieShow { Title = "The Dark Knight", StartTime = DateTime.Now.AddHours(5), Duration = 152, AvailableSeats = 100 }
                    );
                    db.SaveChanges();
                }
            }

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapGet("/movies", async (AppDbContext db) => {

                await db.MovieShows.ToListAsync();

             });

            app.MapGet("/movies/{id:int}", async (int id, AppDbContext db) =>
            {
                var movie = await db.MovieShows.FindAsync(id);
                return movie is not null ? Results.Ok(movie) : Results.NotFound("Not found");
            });

          

            
            app.MapGet("/auth/register", async (string email, string password, string name, AppDbContext db) =>
            {
                if (await db.Users.AnyAsync(u => u.Email == email))
                {
                    return Results.BadRequest("Email already in use");
                }

                var user = new User
                {
                    Email = email,
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword(password),
                    Name = name
                };
                db.Users.Add(user);
                await db.SaveChangesAsync();
                return Results.Ok("User registered successfully");
            });

           
            app.MapGet("/auth/login", async (string email, string password, AppDbContext db, HttpContext context) =>
            {
                var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
                if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.PasswordHash)){
                    return Results.BadRequest("Invalid email or password");
                }

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Name, user.Name ?? "")
                };

                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
                return Results.Ok("User logged in successfully");
            });

            app.MapGet("/auth/logout", async (HttpContext context) =>
            {
                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                return Results.Ok("User logged out successfully");
            });

           
            var cookieBookings = app.MapGroup("/bookings").RequireAuthorization();

            cookieBookings.MapGet("/", async (ClaimsPrincipal principal, AppDbContext db) =>
            {
                var userId = int.Parse(principal.FindFirstValue(ClaimTypes.NameIdentifier)!);
                var bookings = await db.Bookings.Where(b => b.UserId == userId).ToListAsync();
                return Results.Ok(bookings);
            });

            cookieBookings.MapGet("/create", async (int movieShowId, int numberOfSeats, ClaimsPrincipal principal, AppDbContext db) =>
            {
                var userId = int.Parse(principal.FindFirstValue(ClaimTypes.NameIdentifier)!);
                var movieShow = await db.MovieShows.FindAsync(movieShowId);

                if (movieShow == null) {
                    return Results.NotFound("Movie show not found");
                }
                if (movieShow.AvailableSeats < numberOfSeats) {
                    return Results.BadRequest("Not enough available seats");
                }

                var booking = new Booking
                {
                    UserId = userId,
                    MovieShowId = movieShowId,
                    NumberOfSeats = numberOfSeats,
                    BookingTime = DateTime.Now
                };
                movieShow.AvailableSeats -= numberOfSeats;
                db.Bookings.Add(booking);
                await db.SaveChangesAsync();
                return Results.Ok(booking);
            });


       
            
            app.MapGet("/jwt/register", async (string email, string password, string name, AppDbContext db) =>
            {
                if (await db.Users.AnyAsync(u => u.Email == email)) {
                    return Results.BadRequest("Email already in use");
                }

                var user = new User
                {
                    Email = email,
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword(password),
                    Name = name
                };
                db.Users.Add(user);
                await db.SaveChangesAsync();
                return Results.Ok("User registered successfully JWT");
            });

         
            app.MapGet("/jwt/login", async (string email, string password, AppDbContext db) =>
            {
                var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
                if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.PasswordHash)){
                    return Results.BadRequest("Invalid email or password");
                }

                var tokenHandler = new JwtSecurityTokenHandler();
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                        new Claim(ClaimTypes.Email, user.Email),
                        new Claim(ClaimTypes.Name, user.Name ?? "")
                    }),
                    Expires = DateTime.UtcNow.AddHours(2),
                    Issuer = JWTIssuer,
                    Audience = JWTAudience,
                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JWTSecret)),
                        SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);
                return Results.Ok(new { token = tokenString });
            });

            
            var jwtBookings = app.MapGroup("/jwt/bookings") .RequireAuthorization(policy => policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme).RequireAuthenticatedUser());

            jwtBookings.MapGet("/", async (ClaimsPrincipal principal, AppDbContext db) =>
            {
                var userId = int.Parse(principal.FindFirst(ClaimTypes.NameIdentifier)!.Value);
                var bookings = await db.Bookings.Where(b => b.UserId == userId).ToListAsync();
                return Results.Ok(bookings);
            });

            app.MapGet("/login-github", async (HttpContext context) =>
            {
              
                var properties = new AuthenticationProperties { RedirectUri = "/auth/external-callback" };
                await context.ChallengeAsync("GitHub", properties);
            });

            app.MapGet("/auth/external-callback", async (HttpContext context, AppDbContext db) =>
            {
               
                var result = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                if (!result.Succeeded || result.Principal == null)
                {
                    return Results.Unauthorized();
                }

             
                var emailClaim = result.Principal.FindFirst(ClaimTypes.Email);

               
                var email = emailClaim?.Value ?? $"{result.Principal.FindFirst(ClaimTypes.Name)?.Value}@github.local";

                var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
                if (user == null)
                {
                    user = new User
                    {
                        Email = email,
                        Name = result.Principal.FindFirst(ClaimTypes.Name)?.Value ?? "GitHub User",
                        PasswordHash = "" 
                    };
                    db.Users.Add(user);
                    await db.SaveChangesAsync();
                }

                
                await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, result.Principal);
                return Results.Ok(new { message = "User logged in with GitHub successfully", user = user.Name });
            });

            app.Run();
        }
    }
}