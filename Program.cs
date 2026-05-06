using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Serilog;

namespace UserRegistration
{
    public class RegistrationResult
    {
        public bool IsSuccess { get; set; }
        public string Message { get; set; }

        public RegistrationResult()
        {
            IsSuccess = false;
            Message = string.Empty;
        }
    }

    public static class UserValidator
    {
        private static readonly HashSet<string> ForbiddenLogins = new HashSet<string>
        {
            "admin", "root", "user", "test", "guest", "system", "moderator"
        };

        private const string PhonePattern = @"^\+[1-9]\d-\d{3}-\d{3}-\d{4}$";
        private const string EmailPattern = @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";
        private const string LoginStringPattern = @"^[a-zA-Z0-9_]{5,}$";

        public static RegistrationResult ValidateRegistration(string login, string password, string confirmPassword)
        {
            var result = new RegistrationResult();
            string maskedPassword = MaskPassword(password);
            string maskedConfirm = MaskPassword(confirmPassword);

            try
            {
                if (string.IsNullOrEmpty(login))
                {
                    result.Message = "Логин не может быть пустым";
                    LogError(login, maskedPassword, maskedConfirm, result.Message);
                    return result;
                }

                if (!IsValidLogin(login))
                {
                    result.Message = GetLoginErrorMessage(login);
                    LogError(login, maskedPassword, maskedConfirm, result.Message);
                    return result;
                }

                if (IsLoginForbidden(login))
                {
                    result.Message = $"Логин '{login}' запрещен. Используйте другой логин";
                    LogError(login, maskedPassword, maskedConfirm, result.Message);
                    return result;
                }

                if (string.IsNullOrEmpty(password))
                {
                    result.Message = "Пароль не может быть пустым";
                    LogError(login, maskedPassword, maskedConfirm, result.Message);
                    return result;
                }

                if (!IsValidPassword(password))
                {
                    result.Message = GetPasswordErrorMessage(password);
                    LogError(login, maskedPassword, maskedConfirm, result.Message);
                    return result;
                }

                if (password != confirmPassword)
                {
                    result.Message = "Пароль и подтверждение пароля не совпадают";
                    LogError(login, maskedPassword, maskedConfirm, result.Message);
                    return result;
                }

                result.IsSuccess = true;
                result.Message = string.Empty;
                LogSuccess(login, maskedPassword, maskedConfirm);
                return result;
            }
            catch (Exception ex)
            {
                result.Message = $"Внутренняя ошибка: {ex.Message}";
                LogError(login, maskedPassword, maskedConfirm, result.Message, ex);
                return result;
            }
        }

        private static bool IsValidLogin(string login)
        {
            if (Regex.IsMatch(login, PhonePattern)) return true;
            if (Regex.IsMatch(login, EmailPattern)) return true;
            if (Regex.IsMatch(login, LoginStringPattern)) return true;
            return false;
        }

        private static string GetLoginErrorMessage(string login)
        {
            if (Regex.IsMatch(login, @"^\+?\d[\d\-]*$"))
                return "Неверный формат телефона. Используйте формат: +X-XXX-XXX-XXXX";

            if (login.Contains("@") && login.Contains("."))
                return "Неверный формат email. Используйте формат: user@domain.com";

            if (login.Length < 5)
                return "Логин должен содержать минимум 5 символов";

            if (!Regex.IsMatch(login, @"^[a-zA-Z0-9_]+$"))
                return "Логин может содержать только латиницу, цифры и знак подчеркивания";

            return "Неверный формат логина";
        }

        private static bool IsLoginForbidden(string login)
        {
            return ForbiddenLogins.Contains(login.ToLower());
        }

        private static bool IsValidPassword(string password)
        {
            if (password.Length < 7)
                return false;

            bool hasUpper = false;
            bool hasLower = false;
            bool hasDigit = false;
            bool hasSpecial = false;

            foreach (char c in password)
            {
                if (char.IsUpper(c)) hasUpper = true;
                else if (char.IsLower(c)) hasLower = true;
                else if (char.IsDigit(c)) hasDigit = true;
                else if (IsSpecialCharacter(c)) hasSpecial = true;

                if (!IsValidPasswordChar(c))
                    return false;
            }

            return hasUpper && hasLower && hasDigit && hasSpecial;
        }

        private static bool IsValidPasswordChar(char c)
        {
            if (char.IsLetter(c))
            {
                char lower = char.ToLower(c);
                return (lower >= 'а' && lower <= 'я') || lower == 'ё';
            }
            return char.IsDigit(c) || IsSpecialCharacter(c);
        }

        private static bool IsSpecialCharacter(char c)
        {
            return "!@#$%^&*()_+-=[]{};:'\"\\|,.<>/?`~".Contains(c);
        }

        private static string GetPasswordErrorMessage(string password)
        {
            if (password.Length < 7)
                return "Пароль должен содержать минимум 7 символов";

            bool hasUpper = password.Any(char.IsUpper);
            bool hasLower = password.Any(char.IsLower);
            bool hasDigit = password.Any(char.IsDigit);
            bool hasSpecial = password.Any(IsSpecialCharacter);
            bool hasInvalidChars = password.Any(c => !IsValidPasswordChar(c));

            if (hasInvalidChars)
                return "Пароль может содержать только кириллицу, цифры и спецсимволы";

            if (!hasUpper)
                return "Пароль должен содержать хотя бы одну заглавную букву";

            if (!hasLower)
                return "Пароль должен содержать хотя бы одну строчную букву";

            if (!hasDigit)
                return "Пароль должен содержать хотя бы одну цифру";

            if (!hasSpecial)
                return "Пароль должен содержать хотя бы один спецсимвол";

            return "Пароль не соответствует требованиям";
        }

        private static string MaskPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                return "****";

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                string hash = Convert.ToBase64String(hashBytes);
                return hash.Substring(0, Math.Min(8, hash.Length));
            }
        }

        private static void LogSuccess(string login, string maskedPassword, string maskedConfirm)
        {
            Log.Information("УСПЕШНАЯ РЕГИСТРАЦИЯ | Логин: {Login} | Пароль: {MaskedPwd} | Подтверждение: {MaskedConfirm}",
                login, maskedPassword, maskedConfirm);
        }

        private static void LogError(string login, string maskedPassword, string maskedConfirm, string errorMessage, Exception ex = null)
        {
            if (ex != null)
                Log.Error(ex, "НЕУСПЕШНАЯ РЕГИСТРАЦИЯ | Логин: {Login} | Пароль: {MaskedPwd} | Подтверждение: {MaskedConfirm} | Ошибка: {Error}",
                    login, maskedPassword, maskedConfirm, errorMessage);
            else
                Log.Error("НЕУСПЕШНАЯ РЕГИСТРАЦИЯ | Логин: {Login} | Пароль: {MaskedPwd} | Подтверждение: {MaskedConfirm} | Ошибка: {Error}",
                    login, maskedPassword, maskedConfirm, errorMessage);
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            string template = "{Timestamp:HH:mm:ss} | [{Level:u3}] | {Message:lj}{NewLine}{Exception}";

            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.Console(outputTemplate: template)
                .WriteTo.File("logs/registration_log_.txt",
                    outputTemplate: template,
                    rollingInterval: RollingInterval.Day,
                    retainedFileCountLimit: 30)
                .CreateLogger();

            Log.Information("Приложение запущено");

            bool exit = false;
            while (!exit)
            {
                Console.Clear();
                Console.WriteLine("РЕГИСТРАЦИЯ ПОЛЬЗОВАТЕЛЯ");
                Console.WriteLine();
                Console.WriteLine("Требования к логину:");
                Console.WriteLine("  Телефон: +X-XXX-XXX-XXXX");
                Console.WriteLine("  Email: user@domain.com");
                Console.WriteLine("  Строка: минимум 5 символов (латиница, цифры, _)");
                Console.WriteLine("  Запрещенные логины: admin, root, user, test, guest, system, moderator");
                Console.WriteLine();
                Console.WriteLine("Требования к паролю:");
                Console.WriteLine("  Минимум 7 символов");
                Console.WriteLine("  Только кириллица, цифры и спецсимволы");
                Console.WriteLine("  Обязательно: заглавная буква, строчная буква, цифра, спецсимвол");
                Console.WriteLine();

                Console.Write("Введите логин: ");
                string login = Console.ReadLine();

                Console.Write("Введите пароль: ");
                string password = ReadPassword();

                Console.Write("Подтвердите пароль: ");
                string confirmPassword = ReadPassword();

                Console.WriteLine();

                var result = UserValidator.ValidateRegistration(login, password, confirmPassword);

                if (result.IsSuccess)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("РЕЗУЛЬТАТ: True");
                    Console.WriteLine("СООБЩЕНИЕ: Регистрация успешно завершена!");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("РЕЗУЛЬТАТ: False");
                    Console.WriteLine($"СООБЩЕНИЕ: {result.Message}");
                    Console.ResetColor();
                }

                Console.WriteLine();
                Console.Write("Проверить еще? (Y/N): ");
                string choice = Console.ReadLine()?.ToUpper();
                exit = choice != "Y";
            }

            Log.Information("Приложение завершено");
            Log.CloseAndFlush();

            Console.WriteLine();
            Console.WriteLine("Логи сохранены в папке 'logs'");
            Console.WriteLine("Нажмите любую клавишу для выхода...");
            Console.ReadKey();
        }

        private static string ReadPassword()
        {
            string password = string.Empty;
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true);

                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    password += key.KeyChar;
                    Console.Write("*");
                }
                else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password = password.Substring(0, password.Length - 1);
                    Console.Write("\b \b");
                }
            }
            while (key.Key != ConsoleKey.Enter);

            Console.WriteLine();
            return password;
        }
    }
}