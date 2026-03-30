using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace SimpleApiServer13
{
    internal class Program
    {
        private const string JwtIssuer = "SimpleApiServer";
        private const string JwtAudience = "SimpleApiClient";
        private const int JwtLifetimeMinutes = 60;
        private static readonly string JwtSecret = "MySuperSecretKeyForJwtAuthentication2025!";
        private static readonly SymmetricSecurityKey JwtSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSecret));

        static readonly JsonSerializerOptions _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        static List<TaskItem> _tasks = new List<TaskItem>
        {
            new TaskItem { Id = 1, Title = "Сделать лабораторную", Description = "Выполнить ЛР 11 по расширению API", IsCompleted = false, Priority = 2, CreatedAt = DateTime.UtcNow.AddDays(-2), DueDate = DateTime.UtcNow.AddDays(1) },
            new TaskItem { Id = 2, Title = "Проверить почту", Description = "Ответить на письма от преподавателя", IsCompleted = true, Priority = 1, CreatedAt = DateTime.UtcNow.AddDays(-5), DueDate = null },
        };

        static List<User> _users = new List<User>();

        static async Task Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            _users.Add(new User
            {
                Id = 1,
                Email = "test@example.com",
                PasswordHash = HashPassword("password123"),
                Name = "Test User"
            });

            HttpListener listener = new HttpListener();
            listener.Prefixes.Add("http://localhost:5000/");

            try
            {
                listener.Start();
                Console.WriteLine("Сервер запущен: http://localhost:5000/");
                Console.WriteLine("\n=== Endpoints ===");
                Console.WriteLine("AUTH (публичные):");
                Console.WriteLine("  POST /api/auth/register - регистрация");
                Console.WriteLine("  POST /api/auth/login    - вход (возврат JWT)");
                Console.WriteLine("\nTASKS (защищённые, требуют токен):");
                Console.WriteLine("  GET/POST  /api/tasks          - список/создание");
                Console.WriteLine("  GET/PUT/DELETE /api/tasks/{id} - работа по ID");
                Console.WriteLine("\nПараметры: ?isCompleted=..., ?priority=..., ?orderBy=..., ?page=...");
                Console.WriteLine("Заголовок авторизации: Authorization: Bearer <token>");
                Console.WriteLine("Ctrl+C для остановки.\n");

                while (true)
                {
                    HttpListenerContext context = await listener.GetContextAsync();
                    _ = Task.Run(() => HandleRequest(context));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка сервера: {ex.Message}");
            }
            finally
            {
                listener.Stop();
                listener.Close();
                Console.WriteLine("Сервер остановлен.");
            }
        }

        static void HandleRequest(HttpListenerContext context)
        {
            var request = context.Request;
            var response = context.Response;
            string path = request.Url.AbsolutePath;
            string method = request.HttpMethod;

            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {method} {request.Url.PathAndQuery}");

            try
            {
                if (path.StartsWith("/api/auth/"))
                {
                    if (path == "/api/auth/register" && method == "POST")
                        HandleRegister(request, response);
                    else if (path == "/api/auth/login" && method == "POST")
                        HandleLogin(request, response);
                    else
                        WriteError(response, 404, "Endpoint not found", "NOT_FOUND");
                    return;
                }

                if (path == "/api/tasks" || path == "/api/tasks/" || path.StartsWith("/api/tasks/"))
                {
                    if (!CheckAuthorization(request, response, out ClaimsPrincipal user))
                        return;

                    int? userId = null;
                    var idClaim = user?.FindFirst(ClaimTypes.NameIdentifier);
                    if (idClaim != null && int.TryParse(idClaim.Value, out int uid))
                        userId = uid;

                    if (path == "/api/tasks" || path == "/api/tasks/")
                    {
                        if (method == "GET") HandleGetTasks(request, response);
                        else if (method == "POST") HandleCreateTask(request, response, userId);
                        else WriteError(response, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                    }
                    else if (path.StartsWith("/api/tasks/"))
                    {
                        string idPart = path.Substring("/api/tasks/".Length);
                        int slashIndex = idPart.IndexOf('/');
                        if (slashIndex >= 0) idPart = idPart.Substring(0, slashIndex);

                        if (int.TryParse(idPart, out int id))
                        {
                            if (method == "GET") HandleGetTaskById(request, response, id);
                            else if (method == "PUT") HandleUpdateTask(request, response, id, userId);
                            else if (method == "DELETE") HandleDeleteTask(request, response, id, userId);
                            else WriteError(response, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                        }
                        else WriteError(response, 400, "Invalid ID format", "INVALID_ID");
                    }
                    else WriteError(response, 404, "Endpoint not found", "NOT_FOUND");
                }
                else WriteError(response, 404, "Endpoint not found", "NOT_FOUND");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка обработки: {ex.Message}");
                WriteError(response, 500, "Internal Server Error", "INTERNAL_ERROR");
            }
        }

        static void HandleRegister(HttpListenerRequest request, HttpListenerResponse response)
        {
            using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                string body = reader.ReadToEnd();
                if (string.IsNullOrWhiteSpace(body))
                {
                    WriteError(response, 400, "Request body cannot be empty", "EMPTY_BODY");
                    return;
                }

                RegisterRequest regData;
                try { regData = JsonSerializer.Deserialize<RegisterRequest>(body, _jsonOptions); }
                catch (JsonException) { WriteError(response, 400, "Invalid JSON format", "INVALID_JSON"); return; }

                var errors = new List<ValidationError>();
                if (string.IsNullOrWhiteSpace(regData?.Email))
                    errors.Add(new ValidationError { Field = "Email", Message = "Email обязателен" });
                else if (!regData.Email.Contains("@"))
                    errors.Add(new ValidationError { Field = "Email", Message = "Некорректный формат Email" });

                if (string.IsNullOrWhiteSpace(regData?.Password))
                    errors.Add(new ValidationError { Field = "Password", Message = "Пароль обязателен" });
                else if (regData.Password.Length < 6)
                    errors.Add(new ValidationError { Field = "Password", Message = "Пароль минимум 6 символов" });

                if (errors.Count > 0) { WriteValidationError(response, errors); return; }

                if (_users.Any(u => u.Email.Equals(regData.Email, StringComparison.OrdinalIgnoreCase)))
                {
                    WriteError(response, 400, "Пользователь с таким Email уже существует", "USER_EXISTS");
                    return;
                }

                var newUser = new User
                {
                    Id = _users.Count > 0 ? _users.Max(u => u.Id) + 1 : 1,
                    Email = regData.Email,
                    PasswordHash = HashPassword(regData.Password),
                    Name = regData.Name,
                    CreatedAt = DateTime.UtcNow
                };
                _users.Add(newUser);

                var token = GenerateJwtToken(newUser.Id, newUser.Email);

                var responseData = new
                {
                    message = "Регистрация успешна",
                    user = new { id = newUser.Id, email = newUser.Email, name = newUser.Name },
                    token = token,
                    expiresAt = DateTime.UtcNow.AddMinutes(JwtLifetimeMinutes)
                };

                WriteJson(response, JsonSerializer.Serialize(responseData, _jsonOptions), 201);
                Console.WriteLine($"Зарегистрирован пользователь: {newUser.Email}");
            }
        }

        static void HandleLogin(HttpListenerRequest request, HttpListenerResponse response)
        {
            using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                string body = reader.ReadToEnd();
                if (string.IsNullOrWhiteSpace(body))
                {
                    WriteError(response, 400, "Request body cannot be empty", "EMPTY_BODY");
                    return;
                }

                LoginRequest loginData;
                try { loginData = JsonSerializer.Deserialize<LoginRequest>(body, _jsonOptions); }
                catch (JsonException) { WriteError(response, 400, "Invalid JSON format", "INVALID_JSON"); return; }

                var errors = new List<ValidationError>();
                if (string.IsNullOrWhiteSpace(loginData?.Email))
                    errors.Add(new ValidationError { Field = "Email", Message = "Email обязателен" });
                if (string.IsNullOrWhiteSpace(loginData?.Password))
                    errors.Add(new ValidationError { Field = "Password", Message = "Пароль обязателен" });
                if (errors.Count > 0) { WriteValidationError(response, errors); return; }

                var user = _users.FirstOrDefault(u => u.Email.Equals(loginData.Email, StringComparison.OrdinalIgnoreCase));
                if (user == null || !VerifyPassword(loginData.Password, user.PasswordHash))
                {
                    WriteError(response, 401, "Неверный Email или пароль", "INVALID_CREDENTIALS");
                    return;
                }

                var token = GenerateJwtToken(user.Id, user.Email);
                var expiresAt = DateTime.UtcNow.AddMinutes(JwtLifetimeMinutes);

                var responseData = new
                {
                    token = token,
                    email = user.Email,
                    name = user.Name,
                    expiresAt = expiresAt
                };

                WriteJson(response, JsonSerializer.Serialize(responseData, _jsonOptions), 200);
                Console.WriteLine($"Вход выполнен: {user.Email}");
            }
        }

        static bool CheckAuthorization(HttpListenerRequest request, HttpListenerResponse response, out ClaimsPrincipal user)
        {
            user = null;
            string authHeader = request.Headers["Authorization"];

            if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                WriteUnauthorized(response, "Требуется авторизация. Добавьте заголовок: Authorization: Bearer <token>");
                return false;
            }

            string token = authHeader.Substring("Bearer ".Length).Trim();

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var validationParams = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = JwtIssuer,
                    ValidAudience = JwtAudience,
                    IssuerSigningKey = JwtSigningKey,
                    ClockSkew = TimeSpan.Zero
                };

                user = tokenHandler.ValidateToken(token, validationParams, out _);
                return true;
            }
            catch (SecurityTokenExpiredException)
            {
                WriteUnauthorized(response, "Токен истёк. Выполните вход заново.");
                return false;
            }
            catch (SecurityTokenValidationException ex)
            {
                WriteUnauthorized(response, $"Ошибка валидации токена: {ex.GetType().Name}");
                return false;
            }
            catch (Exception)
            {
                WriteUnauthorized(response, "Невалидный токен.");
                return false;
            }
        }

        static string GenerateJwtToken(int userId, string email)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
                new Claim(ClaimTypes.Email, email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            var credentials = new SigningCredentials(JwtSigningKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: JwtIssuer,
                audience: JwtAudience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(JwtLifetimeMinutes),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        static string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(password);
                var hash = sha256.ComputeHash(bytes);
                return Convert.ToBase64String(hash);
            }
        }

        static bool VerifyPassword(string password, string storedHash)
        {
            return HashPassword(password) == storedHash;
        }

        static void WriteUnauthorized(HttpListenerResponse response, string message)
        {
            var errorResponse = new { error = "Unauthorized", message = message };
            WriteJson(response, JsonSerializer.Serialize(errorResponse, _jsonOptions), 401);
        }

        static void HandleGetTasks(HttpListenerRequest request, HttpListenerResponse response)
        {
            var queryParams = ParseQueryString(request.Url.Query);
            var tasks = _tasks.AsQueryable();

            if (queryParams.TryGetValue("isCompleted", out string isCompletedStr) && bool.TryParse(isCompletedStr, out bool isCompleted))
                tasks = tasks.Where(t => t.IsCompleted == isCompleted);

            if (queryParams.TryGetValue("priority", out string priorityStr))
            {
                string p = priorityStr.ToLower();
                if (p == "high" || p == "2") tasks = tasks.Where(t => t.Priority == 2);
                else if (p == "medium" || p == "1") tasks = tasks.Where(t => t.Priority == 1);
                else if (p == "low" || p == "0") tasks = tasks.Where(t => t.Priority == 0);
            }

            if (queryParams.TryGetValue("query", out string searchQuery) && !string.IsNullOrEmpty(searchQuery))
            {
                tasks = tasks.Where(t =>
                    t.Title.IndexOf(searchQuery, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    (t.Description != null && t.Description.IndexOf(searchQuery, StringComparison.OrdinalIgnoreCase) >= 0));
            }

            string orderBy = GetDictValue(queryParams, "orderBy", "createdAt");
            string direction = GetDictValue(queryParams, "direction", "asc").ToLower();

            IOrderedQueryable<TaskItem> orderedTasks;
            var order = orderBy.ToLower();
            var dir = direction == "desc";

            if (order == "id") orderedTasks = dir ? tasks.OrderByDescending(t => t.Id) : tasks.OrderBy(t => t.Id);
            else if (order == "title") orderedTasks = dir ? tasks.OrderByDescending(t => t.Title) : tasks.OrderBy(t => t.Title);
            else if (order == "priority") orderedTasks = dir ? tasks.OrderByDescending(t => t.Priority) : tasks.OrderBy(t => t.Priority);
            else if (order == "duedate") orderedTasks = dir ? tasks.OrderByDescending(t => t.DueDate ?? DateTime.MaxValue) : tasks.OrderBy(t => t.DueDate ?? DateTime.MinValue);
            else if (order == "createdat") orderedTasks = dir ? tasks.OrderByDescending(t => t.CreatedAt) : tasks.OrderBy(t => t.CreatedAt);
            else orderedTasks = tasks.OrderBy(t => t.CreatedAt);

            tasks = orderedTasks;

            int page = 1, pageSize = 10;
            if (int.TryParse(GetDictValue(queryParams, "page", "1"), out int pageVal) && pageVal > 0) page = pageVal;
            if (int.TryParse(GetDictValue(queryParams, "pageSize", "10"), out int ps) && ps > 0 && ps <= 100) pageSize = ps;

            var total = tasks.Count();
            var result = tasks.Skip((page - 1) * pageSize).Take(pageSize).ToList();

            var responseData = new
            {
                data = result,
                error = (object)null,
                meta = new { page, pageSize, total, totalPages = (int)Math.Ceiling(total / (double)pageSize) }
            };

            WriteJson(response, JsonSerializer.Serialize(responseData, _jsonOptions), 200);
        }

        static void HandleGetTaskById(HttpListenerRequest request, HttpListenerResponse response, int id)
        {
            var task = _tasks.FirstOrDefault(t => t.Id == id);
            if (task == null) WriteError(response, 404, $"Task with ID {id} not found", "TASK_NOT_FOUND");
            else WriteSuccess(response, task);
        }

        static void HandleCreateTask(HttpListenerRequest request, HttpListenerResponse response, int? userId)
        {
            using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                string body = reader.ReadToEnd();
                if (string.IsNullOrWhiteSpace(body)) { WriteError(response, 400, "Request body cannot be empty", "EMPTY_BODY"); return; }

                CreateTaskRequest requestData;
                try { requestData = JsonSerializer.Deserialize<CreateTaskRequest>(body, _jsonOptions); }
                catch (JsonException ex) { WriteError(response, 400, $"Invalid JSON format: {ex.Message}", "INVALID_JSON"); return; }

                var errors = new List<ValidationError>();
                if (requestData.Title == null || string.IsNullOrWhiteSpace(requestData.Title))
                    errors.Add(new ValidationError { Field = "Title", Message = "Название обязательно" });
                else if (requestData.Title.Length > 200)
                    errors.Add(new ValidationError { Field = "Title", Message = "Название не более 200 символов" });
                if (requestData.Description != null && requestData.Description.Length > 1000)
                    errors.Add(new ValidationError { Field = "Description", Message = "Описание не более 1000 символов" });
                if (requestData.Priority.HasValue && (requestData.Priority < 1 || requestData.Priority > 5))
                    errors.Add(new ValidationError { Field = "Priority", Message = "Приоритет от 1 до 5" });
                if (requestData.DueDate.HasValue && requestData.DueDate.Value.Date < DateTime.UtcNow.Date)
                    errors.Add(new ValidationError { Field = "DueDate", Message = "Срок не может быть в прошлом" });

                if (errors.Count > 0) { WriteValidationError(response, errors); return; }

                var newTask = new TaskItem
                {
                    Id = _tasks.Count > 0 ? _tasks.Max(t => t.Id) + 1 : 1,
                    Title = requestData.Title ?? "Без названия",
                    Description = requestData.Description,
                    IsCompleted = requestData.IsCompleted ?? false,
                    Priority = requestData.Priority ?? 0,
                    CreatedAt = DateTime.UtcNow,
                    DueDate = requestData.DueDate,
                    CreatedByUserId = userId
                };

                _tasks.Add(newTask);
                response.Headers.Add("Location", $"http://localhost:5000/api/tasks/{newTask.Id}");
                WriteSuccess(response, newTask, 201);
                Console.WriteLine($"Создана задача #{newTask.Id} пользователем {userId}");
            }
        }

        static void HandleUpdateTask(HttpListenerRequest request, HttpListenerResponse response, int id, int? userId)
        {
            var task = _tasks.FirstOrDefault(t => t.Id == id);
            if (task == null) { WriteError(response, 404, $"Task with ID {id} not found", "TASK_NOT_FOUND"); return; }

            using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                string body = reader.ReadToEnd();
                if (string.IsNullOrWhiteSpace(body)) { WriteError(response, 400, "Request body cannot be empty", "EMPTY_BODY"); return; }

                CreateTaskRequest requestData;
                try { requestData = JsonSerializer.Deserialize<CreateTaskRequest>(body, _jsonOptions); }
                catch (JsonException ex) { WriteError(response, 400, $"Invalid JSON format: {ex.Message}", "INVALID_JSON"); return; }

                var errors = new List<ValidationError>();
                if (requestData.Title != null)
                {
                    if (string.IsNullOrWhiteSpace(requestData.Title))
                        errors.Add(new ValidationError { Field = "Title", Message = "Название не может быть пустым" });
                    else if (requestData.Title.Length > 200)
                        errors.Add(new ValidationError { Field = "Title", Message = "Название не более 200 символов" });
                }
                if (requestData.Description != null && requestData.Description.Length > 1000)
                    errors.Add(new ValidationError { Field = "Description", Message = "Описание не более 1000 символов" });
                if (requestData.Priority.HasValue && (requestData.Priority < 1 || requestData.Priority > 5))
                    errors.Add(new ValidationError { Field = "Priority", Message = "Приоритет от 1 до 5" });
                if (requestData.DueDate.HasValue && requestData.DueDate.Value.Date < DateTime.UtcNow.Date)
                    errors.Add(new ValidationError { Field = "DueDate", Message = "Срок не может быть в прошлом" });

                if (errors.Count > 0) { WriteValidationError(response, errors); return; }

                if (requestData.Title != null) task.Title = requestData.Title;
                if (requestData.Description != null) task.Description = requestData.Description;
                if (requestData.Priority.HasValue) task.Priority = requestData.Priority.Value;
                if (requestData.DueDate.HasValue) task.DueDate = requestData.DueDate;
                if (requestData.IsCompleted.HasValue) task.IsCompleted = requestData.IsCompleted.Value;

                WriteSuccess(response, task);
                Console.WriteLine($"Обновлена задача #{id} пользователем {userId}");
            }
        }

        static void HandleDeleteTask(HttpListenerRequest request, HttpListenerResponse response, int id, int? userId)
        {
            var task = _tasks.FirstOrDefault(t => t.Id == id);
            if (task == null) { WriteError(response, 404, $"Task with ID {id} not found", "TASK_NOT_FOUND"); return; }

            _tasks.Remove(task);
            WriteSuccess(response, new { message = "Task deleted successfully", id = id });
            Console.WriteLine($"Удалена задача #{id} пользователем {userId}");
        }

        static void WriteSuccess(HttpListenerResponse response, object data, int statusCode = 200)
        {
            var apiResponse = new { data = data, error = (object)null };
            WriteJson(response, JsonSerializer.Serialize(apiResponse, _jsonOptions), statusCode);
        }

        static void WriteError(HttpListenerResponse response, int statusCode, string message, string code)
        {
            var apiResponse = new { data = (object)null, error = new { message = message, code = code } };
            WriteJson(response, JsonSerializer.Serialize(apiResponse, _jsonOptions), statusCode);
        }

        static void WriteValidationError(HttpListenerResponse response, List<ValidationError> errors)
        {
            var errorResponse = new { error = "Ошибка валидации", errors = errors };
            WriteJson(response, JsonSerializer.Serialize(errorResponse, _jsonOptions), 400);
        }

        static void WriteJson(HttpListenerResponse response, string json, int statusCode = 200)
        {
            response.StatusCode = statusCode;
            response.ContentType = "application/json; charset=utf-8";
            response.AddHeader("Access-Control-Allow-Origin", "*");
            var buffer = Encoding.UTF8.GetBytes(json);
            response.ContentLength64 = buffer.Length;
            response.OutputStream.Write(buffer, 0, buffer.Length);
            response.Close();
        }

        static Dictionary<string, string> ParseQueryString(string query)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(query) || query == "?") return result;
            query = query.TrimStart('?');
            foreach (var pair in query.Split('&'))
            {
                if (string.IsNullOrEmpty(pair)) continue;
                var parts = pair.Split(new[] { '=' }, 2);
                string key = Uri.UnescapeDataString(parts[0]);
                string value = parts.Length > 1 ? Uri.UnescapeDataString(parts[1]) : string.Empty;
                result[key] = value;
            }
            return result;
        }

        static string GetDictValue(Dictionary<string, string> dict, string key, string defaultValue)
        {
            return dict.TryGetValue(key, out string val) ? val : defaultValue;
        }
    }

    public class User
    {
        public int Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string? Name { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    public class RegisterRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string? Name { get; set; }
    }

    public class LoginRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class CreateTaskRequest
    {
        public string Title { get; set; } = string.Empty;
        public string? Description { get; set; }
        public bool? IsCompleted { get; set; }
        public int? Priority { get; set; }
        public DateTime? DueDate { get; set; }
    }

    public class ValidationError
    {
        public string Field { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
    }

    public class TaskItem
    {
        public int Id { get; set; }
        public string Title { get; set; } = string.Empty;
        public string? Description { get; set; }
        public bool IsCompleted { get; set; }
        public int Priority { get; set; } = 0;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? DueDate { get; set; }
        public int? CreatedByUserId { get; set; }
    }
}