function form_test(){
                /**
                *checks if input data is correct by using regex
                */
				var cheks = document.getElementsByClassName('reser');
				var name = document.reg_form.name.value;
				var email = document.reg_form.email.value;
				var number = document.reg_form.phone.value;
				var fail = 0;
				var regex1 = /^[A-Z]{1}(([a-z]{1,})?(\'{1})?[A-Za-z]{1,}){1}(([\s|\-]{1}[A-Za-z]{1}(([a-z]{1,})?(\'{1})?[a-z]{1,}){1}){1,})?$/;
				if(regex1.test(name) == false){
				alert("Not a valid name");
				return false;
				}
				var regex2 = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
				if (regex2.test(email)== false){
				alert("Not a valid email");
				return false;
				}
				var regex3 = /^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$/im;
				if (regex3.test(number) == false){
				alert("Not a valid phone-number");
				return false;
				}
				if (fail==0){
				alert("Reservation succesful.")
				return true;
				}
				}
