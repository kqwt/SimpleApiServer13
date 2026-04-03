using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace SimpleApiServer15
{
    internal class Program
    {
        static AppConfig _config = new AppConfig();
        static SymmetricSecurityKey _jwtSigningKey;

        static string _logLevel = "Information";
        static string _logFilePath = "logs/app.log";

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

            _config = LoadConfig();
            ConfigureLogging(_config.LogLevel, _config.LogFilePath);

            _jwtSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.JwtSettings.Secret));

            _users.Add(new User
            {
                Id = 1,
                Email = "test@example.com",
                PasswordHash = HashPassword("password123"),
                Name = "Test User"
            });

            HttpListener listener = new HttpListener();
            foreach (var url in _config.ListenUrls)
            {
                listener.Prefixes.Add(url);
            }

            try
            {
                listener.Start();
                LogInfo($"Сервер запущен: {string.Join(", ", _config.ListenUrls)}");
                LogInfo($"Уровень логирования: {_logLevel}");
                LogInfo($"Путь к логам: {_logFilePath}");

                Console.WriteLine("\n=== Endpoints ===");
                Console.WriteLine("AUTH (публичные):");
                Console.WriteLine("  POST /api/auth/register - регистрация");
                Console.WriteLine("  POST /api/auth/login    - вход (возврат JWT)");
                Console.WriteLine("\nTASKS (защищённые):");
                Console.WriteLine("  GET/POST  /api/tasks          - список/создание");
                Console.WriteLine("  GET/PUT/DELETE /api/tasks/{id} - работа по ID");
                Console.WriteLine("\nЗаголовок: Authorization: Bearer <token>");
                Console.WriteLine("Ctrl+C для остановки.\n");

                while (true)
                {
                    HttpListenerContext context = await listener.GetContextAsync();
                    _ = Task.Run(() => HandleRequest(context));
                }
            }
            catch (Exception ex)
            {
                LogError($"Ошибка сервера: {ex.Message}", ex);
            }
            finally
            {
                listener.Stop();
                listener.Close();
                LogInfo("Сервер остановлен.");
            }
        }

        static AppConfig LoadConfig()
        {
            var configPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");

            if (!File.Exists(configPath))
            {
                Console.WriteLine($" Файл конфигурации не найден: {configPath}");
                return new AppConfig();
            }

            var json = File.ReadAllText(configPath);
            var config = JsonSerializer.Deserialize<AppConfig>(json, _jsonOptions);

            var port = Environment.GetEnvironmentVariable("API_PORT");
            if (!string.IsNullOrEmpty(port))
            {
                config.ListenUrls = new[] { $"http://localhost:{port}/" };
                LogInfo($"Порт переопределён из переменной окружения: {port}");
            }

            var logLevel = Environment.GetEnvironmentVariable("LOG_LEVEL");
            if (!string.IsNullOrEmpty(logLevel))
            {
                config.LogLevel = logLevel;
            }

            return config!;
        }

        static void ConfigureLogging(string logLevel, string logFilePath)
        {
            _logLevel = logLevel;
            _logFilePath = logFilePath;

            var logDir = Path.GetDirectoryName(_logFilePath);
            if (!string.IsNullOrEmpty(logDir) && !Directory.Exists(logDir))
            {
                Directory.CreateDirectory(logDir);
            }
        }

        static void LogInfo(string message) => WriteLog("INFO", message);
        static void LogWarning(string message) => WriteLog("WARNING", message);
        static void LogError(string message, Exception? ex = null)
        {
            var logMessage = ex != null ? $"{message}: {ex.Message}" : message;
            WriteLog("ERROR", logMessage);
        }
        static void LogDebug(string message)
        {
            if (_logLevel == "Debug") WriteLog("DEBUG", message);
        }

        static void WriteLog(string level, string message)
        {
            var timestamp = DateTime.UtcNow.ToString("O");
            var logLine = $"{timestamp} [{level}] {message}";

            Console.WriteLine(logLine);

            _ = Task.Run(async () =>
            {
                try
                {
                    await File.AppendAllTextAsync(_logFilePath, logLine + Environment.NewLine);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($" Ошибка записи в лог-файл: {ex.Message}");
                }
            });
        }

        static void HandleRequest(HttpListenerContext context)
        {
            var request = context.Request;
            var response = context.Response;
            string path = request.Url.AbsolutePath;
            string method = request.HttpMethod;

            LogDebug($"{method} {request.Url.PathAndQuery}");
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
                        WriteJson(response, new { error = "NotFound", message = "Endpoint not found" }, 404);
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
                        else WriteJson(response, new { error = "MethodNotAllowed", message = "Method not allowed" }, 405);
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
                            else WriteJson(response, new { error = "MethodNotAllowed", message = "Method not allowed" }, 405);
                        }
                        else WriteJson(response, new { error = "BadRequest", message = "Invalid ID format" }, 400);
                    }
                    else WriteJson(response, new { error = "NotFound", message = "Endpoint not found" }, 404);
                }
                else WriteJson(response, new { error = "NotFound", message = "Endpoint not found" }, 404);
            }
            catch (Exception ex)
            {
                LogError($"Ошибка обработки запроса: {method} {path}", ex);

                var errorResponse = new
                {
                    error = "InternalServerError",
                    message = "Произошла внутренняя ошибка сервера"
                };
                WriteJson(response, errorResponse, 500);
            }
        }

        static void HandleRegister(HttpListenerRequest request, HttpListenerResponse response)
        {
            try
            {
                using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
                {
                    string body = reader.ReadToEnd();
                    if (string.IsNullOrWhiteSpace(body))
                    {
                        WriteJson(response, new { error = "BadRequest", message = "Request body cannot be empty" }, 400);
                        return;
                    }

                    RegisterRequest regData;
                    try { regData = JsonSerializer.Deserialize<RegisterRequest>(body, _jsonOptions); }
                    catch (JsonException)
                    {
                        WriteJson(response, new { error = "BadRequest", message = "Invalid JSON format" }, 400);
                        return;
                    }

                    var errors = new List<object>();
                    if (string.IsNullOrWhiteSpace(regData?.Email))
                        errors.Add(new { field = "Email", message = "Email обязателен" });
                    else if (!regData.Email.Contains("@"))
                        errors.Add(new { field = "Email", message = "Некорректный формат Email" });

                    if (string.IsNullOrWhiteSpace(regData?.Password))
                        errors.Add(new { field = "Password", message = "Пароль обязателен" });
                    else if (regData.Password.Length < 6)
                        errors.Add(new { field = "Password", message = "Пароль минимум 6 символов" });

                    if (errors.Count > 0)
                    {
                        var errorResponse = new { error = "Ошибка валидации", errors };
                        WriteJson(response, errorResponse, 400);
                        return;
                    }

                    if (_users.Any(u => u.Email.Equals(regData.Email, StringComparison.OrdinalIgnoreCase)))
                    {
                        WriteJson(response, new { error = "BadRequest", message = "Пользователь с таким Email уже существует" }, 400);
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
                        expiresAt = DateTime.UtcNow.AddMinutes(_config.JwtSettings.LifetimeMinutes)
                    };

                    WriteJson(response, responseData, 201);
                    LogInfo($"Зарегистрирован пользователь: {newUser.Email}");
                }
            }
            catch (Exception ex)
            {
                LogError($"Ошибка в HandleRegister", ex);
                throw;
            }
        }

        static void HandleLogin(HttpListenerRequest request, HttpListenerResponse response)
        {
            try
            {
                using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
                {
                    string body = reader.ReadToEnd();
                    if (string.IsNullOrWhiteSpace(body))
                    {
                        WriteJson(response, new { error = "BadRequest", message = "Request body cannot be empty" }, 400);
                        return;
                    }

                    LoginRequest loginData;
                    try { loginData = JsonSerializer.Deserialize<LoginRequest>(body, _jsonOptions); }
                    catch (JsonException)
                    {
                        WriteJson(response, new { error = "BadRequest", message = "Invalid JSON format" }, 400);
                        return;
                    }

                    var errors = new List<object>();
                    if (string.IsNullOrWhiteSpace(loginData?.Email))
                        errors.Add(new { field = "Email", message = "Email обязателен" });
                    if (string.IsNullOrWhiteSpace(loginData?.Password))
                        errors.Add(new { field = "Password", message = "Пароль обязателен" });
                    if (errors.Count > 0)
                    {
                        var errorResponse = new { error = "Ошибка валидации", errors };
                        WriteJson(response, errorResponse, 400);
                        return;
                    }

                    var user = _users.FirstOrDefault(u => u.Email.Equals(loginData.Email, StringComparison.OrdinalIgnoreCase));
                    if (user == null || !VerifyPassword(loginData.Password, user.PasswordHash))
                    {
                        WriteJson(response, new { error = "Unauthorized", message = "Неверный Email или пароль" }, 401);
                        return;
                    }

                    var token = GenerateJwtToken(user.Id, user.Email);
                    var expiresAt = DateTime.UtcNow.AddMinutes(_config.JwtSettings.LifetimeMinutes);

                    var responseData = new
                    {
                        token = token,
                        email = user.Email,
                        name = user.Name,
                        expiresAt = expiresAt
                    };

                    WriteJson(response, responseData, 200);
                    LogInfo($"Вход выполнен: {user.Email}");
                }
            }
            catch (Exception ex)
            {
                LogError($"Ошибка в HandleLogin", ex);
                throw;
            }
        }

        static bool CheckAuthorization(HttpListenerRequest request, HttpListenerResponse response, out ClaimsPrincipal user)
        {
            user = null;
            string authHeader = request.Headers["Authorization"];

            if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                WriteJson(response, new { error = "Unauthorized", message = "Требуется авторизация. Добавьте заголовок: Authorization: Bearer <token>" }, 401);
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
                    ValidIssuer = _config.JwtSettings.Issuer,
                    ValidAudience = _config.JwtSettings.Audience,
                    IssuerSigningKey = _jwtSigningKey,
                    ClockSkew = TimeSpan.Zero
                };

                user = tokenHandler.ValidateToken(token, validationParams, out _);
                LogDebug($"Токен валидирован для пользователя: {user.FindFirst(ClaimTypes.Email)?.Value}");
                return true;
            }
            catch (SecurityTokenExpiredException)
            {
                WriteJson(response, new { error = "Unauthorized", message = "Токен истёк. Выполните вход заново." }, 401);
                return false;
            }
            catch (SecurityTokenValidationException)
            {
                WriteJson(response, new { error = "Unauthorized", message = "Невалидный токен." }, 401);
                return false;
            }
            catch (Exception)
            {
                WriteJson(response, new { error = "Unauthorized", message = "Ошибка авторизации." }, 401);
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

            var credentials = new SigningCredentials(_jwtSigningKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _config.JwtSettings.Issuer,
                audience: _config.JwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_config.JwtSettings.LifetimeMinutes),
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

        static void HandleGetTasks(HttpListenerRequest request, HttpListenerResponse response)
        {
            try
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

                WriteJson(response, responseData, 200);
                LogDebug($"GET /api/tasks: возвращено {result.Count} задач");
            }
            catch (Exception ex)
            {
                LogError($"Ошибка в HandleGetTasks", ex);
                throw;
            }
        }

        static void HandleGetTaskById(HttpListenerRequest request, HttpListenerResponse response, int id)
        {
            try
            {
                var task = _tasks.FirstOrDefault(t => t.Id == id);
                if (task == null)
                {
                    WriteJson(response, new { error = "NotFound", message = $"Task with ID {id} not found" }, 404);
                    return;
                }
                WriteJson(response, new { data = task, error = (object)null }, 200);
                LogDebug($"GET /api/tasks/{id}: задача найдена");
            }
            catch (Exception ex)
            {
                LogError($"Ошибка в HandleGetTaskById", ex);
                throw;
            }
        }

        static void HandleCreateTask(HttpListenerRequest request, HttpListenerResponse response, int? userId)
        {
            try
            {
                using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
                {
                    string body = reader.ReadToEnd();
                    if (string.IsNullOrWhiteSpace(body))
                    {
                        WriteJson(response, new { error = "BadRequest", message = "Request body cannot be empty" }, 400);
                        return;
                    }

                    CreateTaskRequest requestData;
                    try { requestData = JsonSerializer.Deserialize<CreateTaskRequest>(body, _jsonOptions); }
                    catch (JsonException ex)
                    {
                        WriteJson(response, new { error = "BadRequest", message = $"Invalid JSON format: {ex.Message}" }, 400);
                        return;
                    }

                    var errors = new List<object>();
                    if (requestData.Title == null || string.IsNullOrWhiteSpace(requestData.Title))
                        errors.Add(new { field = "Title", message = "Название обязательно" });
                    else if (requestData.Title.Length > 200)
                        errors.Add(new { field = "Title", message = "Название не более 200 символов" });
                    if (requestData.Description != null && requestData.Description.Length > 1000)
                        errors.Add(new { field = "Description", message = "Описание не более 1000 символов" });
                    if (requestData.Priority.HasValue && (requestData.Priority < 1 || requestData.Priority > 5))
                        errors.Add(new { field = "Priority", message = "Приоритет от 1 до 5" });
                    if (requestData.DueDate.HasValue && requestData.DueDate.Value.Date < DateTime.UtcNow.Date)
                        errors.Add(new { field = "DueDate", message = "Срок не может быть в прошлом" });

                    if (errors.Count > 0)
                    {
                        var errorResponse = new { error = "Ошибка валидации", errors };
                        WriteJson(response, errorResponse, 400);
                        return;
                    }

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
                    WriteJson(response, new { data = newTask, error = (object)null }, 201);
                    LogInfo($"Создана задача #{newTask.Id} пользователем {userId}");
                }
            }
            catch (Exception ex)
            {
                LogError($"Ошибка в HandleCreateTask", ex);
                throw;
            }
        }

        static void HandleUpdateTask(HttpListenerRequest request, HttpListenerResponse response, int id, int? userId)
        {
            try
            {
                var task = _tasks.FirstOrDefault(t => t.Id == id);
                if (task == null)
                {
                    WriteJson(response, new { error = "NotFound", message = $"Task with ID {id} not found" }, 404);
                    return;
                }

                using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
                {
                    string body = reader.ReadToEnd();
                    if (string.IsNullOrWhiteSpace(body))
                    {
                        WriteJson(response, new { error = "BadRequest", message = "Request body cannot be empty" }, 400);
                        return;
                    }

                    CreateTaskRequest requestData;
                    try { requestData = JsonSerializer.Deserialize<CreateTaskRequest>(body, _jsonOptions); }
                    catch (JsonException ex)
                    {
                        WriteJson(response, new { error = "BadRequest", message = $"Invalid JSON format: {ex.Message}" }, 400);
                        return;
                    }

                    var errors = new List<object>();
                    if (requestData.Title != null)
                    {
                        if (string.IsNullOrWhiteSpace(requestData.Title))
                            errors.Add(new { field = "Title", message = "Название не может быть пустым" });
                        else if (requestData.Title.Length > 200)
                            errors.Add(new { field = "Title", message = "Название не более 200 символов" });
                    }
                    if (requestData.Description != null && requestData.Description.Length > 1000)
                        errors.Add(new { field = "Description", message = "Описание не более 1000 символов" });
                    if (requestData.Priority.HasValue && (requestData.Priority < 1 || requestData.Priority > 5))
                        errors.Add(new { field = "Priority", message = "Приоритет от 1 до 5" });
                    if (requestData.DueDate.HasValue && requestData.DueDate.Value.Date < DateTime.UtcNow.Date)
                        errors.Add(new { field = "DueDate", message = "Срок не может быть в прошлом" });

                    if (errors.Count > 0)
                    {
                        var errorResponse = new { error = "Ошибка валидации", errors };
                        WriteJson(response, errorResponse, 400);
                        return;
                    }

                    if (requestData.Title != null) task.Title = requestData.Title;
                    if (requestData.Description != null) task.Description = requestData.Description;
                    if (requestData.Priority.HasValue) task.Priority = requestData.Priority.Value;
                    if (requestData.DueDate.HasValue) task.DueDate = requestData.DueDate;
                    if (requestData.IsCompleted.HasValue) task.IsCompleted = requestData.IsCompleted.Value;

                    WriteJson(response, new { data = task, error = (object)null }, 200);
                    LogInfo($"Обновлена задача #{id} пользователем {userId}");
                }
            }
            catch (Exception ex)
            {
                LogError($"Ошибка в HandleUpdateTask", ex);
                throw;
            }
        }

        static void HandleDeleteTask(HttpListenerRequest request, HttpListenerResponse response, int id, int? userId)
        {
            try
            {
                var task = _tasks.FirstOrDefault(t => t.Id == id);
                if (task == null)
                {
                    WriteJson(response, new { error = "NotFound", message = $"Task with ID {id} not found" }, 404);
                    return;
                }

                _tasks.Remove(task);
                WriteJson(response, new { message = "Task deleted successfully", id = id }, 200);
                LogInfo($"Удалена задача #{id} пользователем {userId}");
            }
            catch (Exception ex)
            {
                LogError($"Ошибка в HandleDeleteTask", ex);
                throw;
            }
        }

        static void WriteJson(HttpListenerResponse response, object data, int statusCode = 200)
        {
            response.StatusCode = statusCode;
            response.ContentType = "application/json; charset=utf-8";
            response.AddHeader("Access-Control-Allow-Origin", "*");
            var json = JsonSerializer.Serialize(data, _jsonOptions);
            var buffer = Encoding.UTF8.GetBytes(json);
            response.ContentLength64 = buffer.Length;
            response.OutputStream.Write(buffer, 0, buffer.Length);
            response.Close();
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

    public class AppConfig
    {
        public string[] ListenUrls { get; set; } = new[] { "http://localhost:5000/" };
        public string LogLevel { get; set; } = "Information";
        public string LogFilePath { get; set; } = "logs/app.log";
        public JwtSettings JwtSettings { get; set; } = new JwtSettings();
    }

    public class JwtSettings
    {
        public string Secret { get; set; } = "DefaultSecretKey!";
        public string Issuer { get; set; } = "SimpleApiServer";
        public string Audience { get; set; } = "SimpleApiClient";
        public int LifetimeMinutes { get; set; } = 60;
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