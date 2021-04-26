using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        public AccountController(DataContext context)
        {
            _context = context;
        }

        [HttpPost("Register")]
        public async Task<ActionResult<AppUser>> Register(RegisterDto registerDto){

            if(await UserExists(registerDto.Username)) return BadRequest("Username is already taken");
            
            using var hmac= new HMACSHA512(); 

            var user=new AppUser
            {
                UserName=registerDto.Username.ToLower(),
                PasswordHash=hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt=hmac.Key
            };

            _context.Add(user);
            await _context.SaveChangesAsync();
             return user;
        }


[HttpPost("Login")]

public async Task<ActionResult<AppUser>> Login(LoginDto loginDto){

//get the user from the DB based on the username supplied
var user= await _context.Users.SingleOrDefaultAsync(x=> x.UserName==loginDto.Username);

//If user not found return status message
if(user==null) return Unauthorized("Invalid Username");

//If user found, we will compute the password hash using the salt 
//saved in DB against the same username to match the PW
using var hmac=new HMACSHA512(user.PasswordSalt);

//calculating hash of the password supplied by the user from frontend
var computedHash=hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

//comparing the two hashes
for(int i=0; i<computedHash.Length; i++ )
{ if(computedHash[i]!=user.PasswordHash[i]) return Unauthorized("Invalid Password"); }

return user;
}



        private async Task<bool> UserExists(string username)
        {
            return await _context.Users.AnyAsync(x=>x.UserName==username.ToLower());

        }
    }
}