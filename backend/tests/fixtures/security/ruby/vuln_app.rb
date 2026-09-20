class UsersController < ApplicationController
  def show
    q = params[:q]
    User.where("name = '#{q}'")
    redirect_to params[:next]
  end

  def run
    cmd = params[:cmd]
    system(cmd)
  end
end
