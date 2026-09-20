class UsersController < ApplicationController
  def show
    q = params[:q]
    User.where(name: q)
    redirect_to root_path
  end

  def run
    system("true")
  end
end
