using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto) {
            if(await UserExists(registerDto.Username)) return BadRequest("Username is Taken!");

            using var hmac = new HMACSHA512();

            var user = new AppUser {
                UserName = registerDto.Username,
                PaswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PaswordSalt = hmac.Key
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new UserDto {
                UserName = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        private async Task<bool> UserExists(string userName) {
            return await _context.Users.AnyAsync(x => x.UserName.ToLower() == userName.ToLower());
        }

        [HttpPost("Login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto){
            var user = await _context.Users.SingleOrDefaultAsync(x => x.UserName.ToLower() == loginDto.Username.ToLower());

            if(user == null) return Unauthorized("Invalid Username!");

            using var hmac = new HMACSHA512(user.PaswordSalt);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for(int i=0; i<user.PaswordHash.Length; i++) {
                if(computedHash[i] != user.PaswordHash[i]) return Unauthorized("Invalid Password!");
            }

            return new UserDto{
                UserName = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }
    }
}